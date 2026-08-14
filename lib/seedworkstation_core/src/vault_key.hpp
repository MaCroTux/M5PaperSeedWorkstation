#pragma once
#include <Arduino.h>
#include <SD.h>
#include <mbedtls/gcm.h>
#include "encrypted_seed_store.hpp"
#include "ble_key.hpp"

// Core2 + PIN: segundo metodo de desbloqueo del Vault de sesion.
//
// El Vault de sesion ya guarda su clave maestra M (32 bytes) cifrada con
// K_pw = PBKDF2(contrasena). Este modulo guarda UNA SEGUNDA copia de M en un
// archivo paralelo (".k2f") cifrada con una clave derivada de DOS factores:
//
//   K_pin = PBKDF2-HMAC-SHA256(PIN, salt, kPinIterations)   (frena fuerza bruta)
//   K_2f  = HMAC-SHA256(key = K_pair, msg = K_pin)          (une llave Core2 + PIN)
//   M2fa  = AES-256-GCM(M, K_2f)
//
// Para desbloquear: BLE auth (el Core2 esta presente) -> introducir PIN ->
// derivar K_2f -> desencriptar M -> cargar semillas.
//
// El Core2 nunca ve M ni el PIN. Perder el Core2 no impide el acceso: la
// contrasena sigue funcionando (recuperacion). El formato M5SM/M5SR no se toca.

namespace vault_2fa {

constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderSize = 64;
constexpr size_t kMasterSize = 32;
constexpr size_t kTagSize = 16;
constexpr uint32_t kPinIterations = 150000;

using Result = encrypted_seed_store::Result;
using ProgressFn = encrypted_seed_store::ProgressFn;

// Layout del header (64 bytes):
//   0..3   "M5K2"
//   4      version
//   5      longitud de la etiqueta (1..16)
//   6..9   vaultId
//   10..25 salt (PBKDF2 del PIN)
//   26..37 nonce (GCM)
//   38..41 reservado
//   42..57 etiqueta
//   58..63 reservado

inline void buildPath(const uint8_t vaultId[4], char* out, size_t n) {
  snprintf(out, n, "/K2F-%02X%02X%02X%02X.k2f",
           vaultId[0], vaultId[1], vaultId[2], vaultId[3]);
}

inline bool deriveK2f(const uint8_t kpair[ble_key::kKeySize], const char* pin,
                      const uint8_t salt[16], uint8_t out[32],
                      ProgressFn progress = nullptr) {
  if (!pin || !pin[0]) return false;
  uint8_t kpin[32] = {};
  if (!encrypted_seed_store::pbkdf2_sha256(pin, salt, kPinIterations, kpin, progress)) {
    encrypted_seed_store::wipe(kpin, sizeof(kpin));
    return false;
  }
  const bool ok = ble_key::hmacSha256(kpair, ble_key::kKeySize, kpin, 32, out);
  encrypted_seed_store::wipe(kpin, sizeof(kpin));
  return ok;
}

inline Result enable(const char* path, const uint8_t master[kMasterSize],
                     const uint8_t vaultId[4], const char* label,
                     const uint8_t kpair[ble_key::kKeySize], const char* pin) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  if (!label || !label[0] || strlen(label) > 16 || !pin || !pin[0]) return Result::invalid_file;
  if (SD.exists(path)) SD.remove(path);
  uint8_t header[kHeaderSize] = {}, cipher[kMasterSize] = {}, key[32] = {}, tag[kTagSize] = {};
  memcpy(header, "M5K2", 4); header[4] = kVersion; header[5] = static_cast<uint8_t>(strlen(label));
  memcpy(header + 6, vaultId, 4);
  esp_fill_random(header + 10, 16);
  esp_fill_random(header + 26, 12);
  memcpy(header + 42, label, strlen(label));
  Result result = Result::crypto_error;
  if (deriveK2f(kpair, pin, header + 10, key)) {
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, kMasterSize,
          header + 26, 12, header, kHeaderSize, master, cipher, kTagSize, tag) == 0) {
      File f = SD.open(path, FILE_WRITE);
      const bool ok = f && f.write(header, sizeof(header)) == sizeof(header) &&
          f.write(cipher, kMasterSize) == kMasterSize &&
          f.write(tag, kTagSize) == kTagSize;
      if (f) { f.flush(); f.close(); }
      result = ok ? Result::ok : Result::io_error;
      if (!ok) SD.remove(path);
    }
    mbedtls_gcm_free(&gcm);
  }
  encrypted_seed_store::wipe(header, sizeof(header));
  encrypted_seed_store::wipe(cipher, sizeof(cipher));
  encrypted_seed_store::wipe(key, sizeof(key));
  encrypted_seed_store::wipe(tag, sizeof(tag));
  return result;
}

inline Result unlock(const char* path, const uint8_t kpair[ble_key::kKeySize],
                     const char* pin, uint8_t master[kMasterSize],
                     uint8_t vaultId[4], char label[17],
                     ProgressFn progress = nullptr) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  File file = SD.open(path, FILE_READ);
  if (!file) return Result::io_error;
  uint8_t header[kHeaderSize] = {}, cipher[kMasterSize] = {}, key[32] = {}, tag[kTagSize] = {};
  Result result = Result::invalid_file;
  if (file.size() != kHeaderSize + kMasterSize + kTagSize ||
      file.read(header, kHeaderSize) != kHeaderSize || memcmp(header, "M5K2", 4) ||
      header[4] != kVersion || header[5] == 0 || header[5] > 16 ||
      file.read(cipher, kMasterSize) != kMasterSize ||
      file.read(tag, kTagSize) != kTagSize) goto cleanup;
  if (!deriveK2f(kpair, pin, header + 10, key, progress)) { result = Result::crypto_error; goto cleanup; }
  {
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    const int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0
        ? mbedtls_gcm_auth_decrypt(&gcm, kMasterSize, header + 26, 12,
            header, kHeaderSize, tag, kTagSize, cipher, master) : -1;
    mbedtls_gcm_free(&gcm);
    if (rc != 0) { result = Result::wrong_password_or_tampered; goto cleanup; }
  }
  memcpy(vaultId, header + 6, 4);
  memcpy(label, header + 42, header[5]);
  label[header[5]] = '\0';
  result = Result::ok;
cleanup:
  file.close();
  encrypted_seed_store::wipe(header, sizeof(header));
  encrypted_seed_store::wipe(cipher, sizeof(cipher));
  encrypted_seed_store::wipe(key, sizeof(key));
  encrypted_seed_store::wipe(tag, sizeof(tag));
  if (result != Result::ok) {
    encrypted_seed_store::wipe(master, kMasterSize);
    memset(vaultId, 0, 4); label[0] = 0;
  }
  return result;
}

inline bool readLabel(const char* path, char label[17]) {
  File f = SD.open(path, FILE_READ);
  if (!f) return false;
  uint8_t header[kHeaderSize] = {};
  const bool ok = f.read(header, kHeaderSize) == kHeaderSize &&
      !memcmp(header, "M5K2", 4) && header[4] == kVersion &&
      header[5] > 0 && header[5] <= 16;
  f.close();
  if (!ok) return false;
  memcpy(label, header + 42, header[5]);
  label[header[5]] = '\0';
  return true;
}

}  // namespace vault_2fa
