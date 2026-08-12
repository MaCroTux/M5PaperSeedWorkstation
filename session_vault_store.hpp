#pragma once

#include <Arduino.h>
#include <SD.h>
#include <mbedtls/gcm.h>

#include "encrypted_seed_store.hpp"

namespace session_vault_store {

constexpr uint8_t kVersion = 2;
constexpr size_t kHeaderSize = 64;
constexpr size_t kTagSize = 16;
constexpr size_t kMasterSize = 32;
constexpr size_t kMaxPlaintext = 49;

using Result = encrypted_seed_store::Result;

inline bool write_file(const char* path, const uint8_t* header,
                       const uint8_t* cipher, size_t cipherLength,
                       const uint8_t tag[kTagSize]) {
  if (SD.exists(path)) return false;
  File file = SD.open(path, FILE_WRITE);
  const bool ok = file && file.write(header, kHeaderSize) == kHeaderSize &&
      file.write(cipher, cipherLength) == cipherLength &&
      file.write(tag, kTagSize) == kTagSize;
  if (file) { file.flush(); file.close(); }
  if (!ok) SD.remove(path);
  return ok;
}

inline Result create(const char* path, const char* label, const char* password,
                     uint8_t master[kMasterSize], uint8_t vaultId[4],
                     encrypted_seed_store::ProgressFn progress = nullptr) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  if (SD.exists(path)) return Result::exists;
  if (!label || !label[0] || strlen(label) > 16) return Result::invalid_file;
  uint8_t header[kHeaderSize] = {}, cipher[kMasterSize] = {}, key[32] = {}, tag[16] = {};
  memcpy(header, "M5SM", 4); header[4] = kVersion; header[5] = strlen(label);
  encrypted_seed_store::put32(header + 6, encrypted_seed_store::kIterations);
  esp_fill_random(header + 10, 16); esp_fill_random(header + 26, 12);
  esp_fill_random(vaultId, 4); memcpy(header + 38, vaultId, 4);
  memcpy(header + 42, label, strlen(label)); esp_fill_random(master, kMasterSize);
  Result result = Result::crypto_error;
  if (encrypted_seed_store::derive(password, header + 10,
          encrypted_seed_store::kIterations, key, progress)) {
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, kMasterSize,
          header + 26, 12, header, kHeaderSize, master, cipher, 16, tag) == 0)
      result = write_file(path, header, cipher, kMasterSize, tag)
                   ? Result::ok : Result::io_error;
    mbedtls_gcm_free(&gcm);
  }
  encrypted_seed_store::wipe(header, sizeof(header));
  encrypted_seed_store::wipe(cipher, sizeof(cipher));
  encrypted_seed_store::wipe(key, sizeof(key)); encrypted_seed_store::wipe(tag, sizeof(tag));
  if (result != Result::ok) { encrypted_seed_store::wipe(master, kMasterSize); memset(vaultId, 0, 4); }
  return result;
}

inline Result unlock(const char* path, const char* password,
                     uint8_t master[kMasterSize], uint8_t vaultId[4],
                     char label[17],
                     encrypted_seed_store::ProgressFn progress = nullptr) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  File file = SD.open(path, FILE_READ); if (!file) return Result::io_error;
  uint8_t header[kHeaderSize] = {}, cipher[kMasterSize] = {}, key[32] = {}, tag[16] = {};
  Result result = Result::invalid_file;
  if (file.size() != kHeaderSize + kMasterSize + kTagSize ||
      file.read(header, kHeaderSize) != kHeaderSize || memcmp(header, "M5SM", 4) ||
      header[4] != kVersion || header[5] == 0 || header[5] > 16 ||
      file.read(cipher, kMasterSize) != kMasterSize || file.read(tag, 16) != 16) goto cleanup;
  if (!encrypted_seed_store::derive(password, header + 10,
          encrypted_seed_store::get32(header + 6), key, progress)) { result = Result::crypto_error; goto cleanup; }
  {
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    const int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0
        ? mbedtls_gcm_auth_decrypt(&gcm, kMasterSize, header + 26, 12,
            header, kHeaderSize, tag, 16, cipher, master) : -1;
    mbedtls_gcm_free(&gcm);
    if (rc != 0) { result = Result::wrong_password_or_tampered; goto cleanup; }
  }
  memcpy(vaultId, header + 38, 4); memcpy(label, header + 42, header[5]);
  label[header[5]] = '\0'; result = Result::ok;
cleanup:
  file.close(); encrypted_seed_store::wipe(header, sizeof(header));
  encrypted_seed_store::wipe(cipher, sizeof(cipher)); encrypted_seed_store::wipe(key, sizeof(key));
  encrypted_seed_store::wipe(tag, sizeof(tag));
  if (result != Result::ok) { encrypted_seed_store::wipe(master, kMasterSize); memset(vaultId, 0, 4); label[0] = 0; }
  return result;
}

inline Result save_seed(const char* path, const uint8_t master[kMasterSize],
                        const uint8_t vaultId[4], const char* label,
                        const uint8_t fingerprint[4], const uint16_t* words,
                        uint8_t count) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  if (SD.exists(path)) return Result::exists;
  if ((count != 12 && count != 24) || !label || !label[0] || strlen(label) > 16)
    return Result::invalid_seed;
  uint8_t header[kHeaderSize] = {}, plain[kMaxPlaintext] = {}, cipher[kMaxPlaintext] = {}, tag[16] = {};
  memcpy(header, "M5SR", 4); header[4] = kVersion; header[5] = count;
  esp_fill_random(header + 6, 12); memcpy(header + 18, vaultId, 4);
  memcpy(header + 22, fingerprint, 4); header[26] = strlen(label);
  memcpy(header + 27, label, strlen(label));
  const uint8_t length = 1 + count * 2; plain[0] = count;
  for (uint8_t i = 0; i < count; ++i) {
    plain[1 + i * 2] = words[i]; plain[2 + i * 2] = words[i] >> 8;
  }
  Result result = Result::crypto_error; mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, master, 256) == 0 &&
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, length,
        header + 6, 12, header, kHeaderSize, plain, cipher, 16, tag) == 0)
    result = write_file(path, header, cipher, length, tag) ? Result::ok : Result::io_error;
  mbedtls_gcm_free(&gcm); encrypted_seed_store::wipe(header, sizeof(header));
  encrypted_seed_store::wipe(plain, sizeof(plain)); encrypted_seed_store::wipe(cipher, sizeof(cipher));
  encrypted_seed_store::wipe(tag, sizeof(tag)); return result;
}

inline Result load_seed(const char* path, const uint8_t master[kMasterSize],
                        const uint8_t vaultId[4], uint16_t* words, uint8_t& count,
                        uint8_t fingerprint[4], char label[17]) {
  File file = SD.open(path, FILE_READ); if (!file) return Result::io_error;
  uint8_t header[kHeaderSize] = {}, plain[kMaxPlaintext] = {}, cipher[kMaxPlaintext] = {}, tag[16] = {};
  Result result = Result::invalid_file;
  if (file.read(header, kHeaderSize) != kHeaderSize || memcmp(header, "M5SR", 4) ||
      header[4] != kVersion || memcmp(header + 18, vaultId, 4) ||
      (header[5] != 12 && header[5] != 24) || header[26] == 0 || header[26] > 16) goto cleanup;
  {
    const uint8_t length = 1 + header[5] * 2;
    if (file.size() != kHeaderSize + length + 16 ||
        file.read(cipher, length) != length || file.read(tag, 16) != 16) goto cleanup;
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    const int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, master, 256) == 0
        ? mbedtls_gcm_auth_decrypt(&gcm, length, header + 6, 12,
            header, kHeaderSize, tag, 16, cipher, plain) : -1;
    mbedtls_gcm_free(&gcm);
    if (rc != 0 || plain[0] != header[5]) { result = Result::wrong_password_or_tampered; goto cleanup; }
    count = plain[0];
    for (uint8_t i = 0; i < count; ++i)
      words[i] = uint16_t(plain[1 + i * 2]) | (uint16_t(plain[2 + i * 2]) << 8);
    memcpy(fingerprint, header + 22, 4); memcpy(label, header + 27, header[26]);
    label[header[26]] = '\0'; result = Result::ok;
  }
cleanup:
  file.close(); encrypted_seed_store::wipe(header, sizeof(header));
  encrypted_seed_store::wipe(plain, sizeof(plain)); encrypted_seed_store::wipe(cipher, sizeof(cipher));
  encrypted_seed_store::wipe(tag, sizeof(tag)); return result;
}

}  // namespace session_vault_store
