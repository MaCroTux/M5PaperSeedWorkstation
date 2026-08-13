#pragma once
#include <Arduino.h>
#include <SD.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

namespace encrypted_seed_store {
constexpr uint8_t kVersion = 1;
constexpr uint32_t kIterations = 600000;
constexpr uint32_t kMaxIterations = 10000000;
constexpr size_t kHeaderSize = 40;
constexpr size_t kTagSize = 16;
constexpr size_t kMaxPlaintext = 49;

enum class Result { ok, no_sd, exists, io_error, invalid_file,
                    wrong_password_or_tampered, invalid_seed, crypto_error };

inline void wipe(void* data, size_t size) {
  volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
  while (size--) *p++ = 0;
}

inline void put32(uint8_t* out, uint32_t value) {
  out[0] = value; out[1] = value >> 8; out[2] = value >> 16; out[3] = value >> 24;
}
inline uint32_t get32(const uint8_t* in) {
  return uint32_t(in[0]) | (uint32_t(in[1]) << 8) |
         (uint32_t(in[2]) << 16) | (uint32_t(in[3]) << 24);
}

using ProgressFn = void (*)(uint32_t done, uint32_t total);

// PBKDF2-HMAC-SHA256 (RFC 2898) para un unico bloque de 32 bytes (dkLen = 32).
// Implementado manualmente para poder informar del progreso durante la
// derivacion, que en este dispositivo tarda varios segundos.
inline bool pbkdf2_sha256(const char* password, const uint8_t salt[16],
                          uint32_t iterations, uint8_t key[32],
                          ProgressFn progress = nullptr) {
  if (!password || !password[0] || iterations == 0) return false;
  const size_t plen = strlen(password);
  mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info || mbedtls_md_setup(&ctx, info, 1) != 0 ||
      mbedtls_md_hmac_starts(&ctx,
          reinterpret_cast<const unsigned char*>(password), plen) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  uint8_t u[32] = {}, t[32] = {}, msg[20] = {};
  memcpy(msg, salt, 16);
  msg[16] = msg[17] = msg[18] = 0; msg[19] = 1;  // INT_32_BE(1)
  if (mbedtls_md_hmac_update(&ctx, msg, sizeof(msg)) != 0 ||
      mbedtls_md_hmac_finish(&ctx, u) != 0) {
    wipe(u, sizeof(u)); wipe(t, sizeof(t)); wipe(msg, sizeof(msg));
    mbedtls_md_free(&ctx);
    return false;
  }
  memcpy(t, u, 32);
  const uint32_t reportEvery = iterations / 50 > 0 ? iterations / 50 : 1;
  uint32_t lastReported = 0;
  for (uint32_t i = 2; i <= iterations; ++i) {
    mbedtls_md_hmac_reset(&ctx);
    if (mbedtls_md_hmac_update(&ctx, u, 32) != 0 ||
        mbedtls_md_hmac_finish(&ctx, u) != 0) {
      wipe(u, sizeof(u)); wipe(t, sizeof(t)); wipe(msg, sizeof(msg));
      mbedtls_md_free(&ctx);
      return false;
    }
    for (uint8_t k = 0; k < 32; ++k) t[k] ^= u[k];
    if (progress && (i - lastReported) >= reportEvery) {
      lastReported = i;
      progress(i, iterations);
    }
  }
  memcpy(key, t, 32);
  wipe(u, sizeof(u)); wipe(t, sizeof(t)); wipe(msg, sizeof(msg));
  mbedtls_md_free(&ctx);
  if (progress) progress(iterations, iterations);
  return true;
}

inline bool derive(const char* password, const uint8_t salt[16],
                   uint32_t iterations, uint8_t key[32],
                   ProgressFn progress = nullptr) {
  if (!password || !password[0] || iterations < 100000 || iterations > kMaxIterations)
    return false;
  return pbkdf2_sha256(password, salt, iterations, key, progress);
}

inline bool self_test() {
  uint8_t manual[32] = {}, reference[32] = {};
  static const uint8_t salt[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  if (!pbkdf2_sha256("password", salt, 1000, manual)) return false;
  mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  bool ok = info && mbedtls_md_setup(&ctx, info, 1) == 0 &&
      mbedtls_pkcs5_pbkdf2_hmac(&ctx,
          reinterpret_cast<const unsigned char*>("password"), 8,
          salt, 16, 1000, 32, reference) == 0;
  mbedtls_md_free(&ctx);
  ok = ok && memcmp(manual, reference, 32) == 0;
  wipe(manual, sizeof(manual)); wipe(reference, sizeof(reference));
  return ok;
}

inline Result save(const char* path, const char* password,
                   const uint16_t* words, uint8_t count,
                   ProgressFn progress = nullptr) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  if (SD.exists(path)) return Result::exists;
  if ((count != 12 && count != 24) || !words) return Result::invalid_seed;
  uint8_t header[kHeaderSize] = {}, plain[kMaxPlaintext] = {};
  uint8_t cipher[kMaxPlaintext] = {}, key[32] = {}, tag[kTagSize] = {};
  memcpy(header, "M5SV", 4); header[4] = kVersion; header[5] = 1;
  put32(header + 6, kIterations);
  esp_fill_random(header + 10, 16);  // salt
  esp_fill_random(header + 26, 12);  // nonce GCM
  const uint8_t plainLength = 1 + count * 2;
  header[38] = plainLength;
  plain[0] = count;
  for (uint8_t i = 0; i < count; ++i) {
    if (words[i] >= 2048) { wipe(plain, sizeof(plain)); return Result::invalid_seed; }
    plain[1 + i * 2] = words[i]; plain[2 + i * 2] = words[i] >> 8;
  }
  Result result = Result::crypto_error;
  if (!derive(password, header + 10, kIterations, key, progress)) goto cleanup;
  {
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plainLength,
          header + 26, 12, header, kHeaderSize, plain, cipher,
          kTagSize, tag) == 0) {
      File file = SD.open(path, FILE_WRITE);
      if (file && file.write(header, sizeof(header)) == sizeof(header) &&
          file.write(cipher, plainLength) == plainLength &&
          file.write(tag, sizeof(tag)) == sizeof(tag)) {
        file.flush(); result = Result::ok;
      } else result = Result::io_error;
      if (file) file.close();
      if (result != Result::ok) SD.remove(path);
    }
    mbedtls_gcm_free(&gcm);
  }
cleanup:
  wipe(plain, sizeof(plain)); wipe(cipher, sizeof(cipher));
  wipe(key, sizeof(key)); wipe(tag, sizeof(tag)); wipe(header, sizeof(header));
  return result;
}

inline Result load(const char* path, const char* password,
                   uint16_t* words, uint8_t& count,
                   ProgressFn progress = nullptr) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  File file = SD.open(path, FILE_READ);
  if (!file) return Result::io_error;
  uint8_t header[kHeaderSize] = {}, cipher[kMaxPlaintext] = {};
  uint8_t plain[kMaxPlaintext] = {}, key[32] = {}, tag[kTagSize] = {};
  Result result = Result::invalid_file;
  if (file.read(header, sizeof(header)) != sizeof(header) ||
      memcmp(header, "M5SV", 4) || header[4] != kVersion || header[5] != 1)
    goto cleanup;
  {
    const uint8_t length = header[38];
    const uint32_t iterations = get32(header + 6);
    if ((length != 25 && length != 49) || iterations < 100000 ||
        iterations > kMaxIterations ||
        file.size() != kHeaderSize + length + kTagSize ||
        file.read(cipher, length) != length || file.read(tag, kTagSize) != kTagSize)
      goto cleanup;
    if (!derive(password, header + 10, iterations, key, progress)) { result = Result::crypto_error; goto cleanup; }
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    const int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0
        ? mbedtls_gcm_auth_decrypt(&gcm, length, header + 26, 12,
            header, kHeaderSize, tag, kTagSize, cipher, plain) : -1;
    mbedtls_gcm_free(&gcm);
    if (rc != 0) { result = Result::wrong_password_or_tampered; goto cleanup; }
    count = plain[0];
    if ((count != 12 && count != 24) || length != 1 + count * 2) goto cleanup;
    for (uint8_t i = 0; i < count; ++i) {
      words[i] = uint16_t(plain[1 + i * 2]) | (uint16_t(plain[2 + i * 2]) << 8);
      if (words[i] >= 2048) { result = Result::invalid_seed; goto cleanup; }
    }
    result = Result::ok;
  }
cleanup:
  file.close(); wipe(header, sizeof(header)); wipe(cipher, sizeof(cipher));
  wipe(plain, sizeof(plain)); wipe(key, sizeof(key)); wipe(tag, sizeof(tag));
  return result;
}
}  // namespace encrypted_seed_store
