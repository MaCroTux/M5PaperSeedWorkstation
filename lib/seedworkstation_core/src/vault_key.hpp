#pragma once
#include <Arduino.h>
#include <SD.h>
#include <mbedtls/gcm.h>
#include "encrypted_seed_store.hpp"
#include "ble_key.hpp"

// Desbloqueo asimetrico del Vault de sesion con el M5Core2 como llave.
//
// MODELO: el Core2 guarda la clave PRIVADA sk (protegida por PIN); el M5Paper
// guarda la clave maestra M del vault cifrada con la clave PUBLICA del Core2
// (ECIES sobre secp256k1). Asi, robar solo el M5Paper no revela nada: hace falta
// el Core2 (con su sk) y el PIN para abrir.
//
//   M5Paper                       M5Core2
//     |  pk (publica, guardada)      |  sk (privada, cifrada con PIN)
//     |  .k2f = header || ECIES(M)   |
//     |                              |
//   Desbloqueo:                      |
//     |-- E_sess || ECIES(M) ------->|  pide PIN -> recupera sk
//     |                              |  M = eciesDecrypt(sk, ECIES(M))
//     |<-- AES-GCM(M, K_sess) -------|  K_sess = ECDH(sk, E_sess)
//     |  M = descifrar               |
//
// El Core2 ve M solo en RAM durante el desbloqueo. M nunca viaja en claro
// (la respuesta va cifrada con la clave de sesion ECIES).
//
// La contraseña del vault sigue siendo un metodo de recuperacion independiente.

namespace vault_2fa {

constexpr uint8_t kVersion = 3;
constexpr size_t kHeaderSize = 64;
constexpr size_t kMasterSize = 32;
constexpr uint32_t kPinIterations = 150000;
// blob ECIES de la maestra: E(65) || nonce(12) || ct(32) || tag(16)
constexpr size_t kBlobSize =
    ble_key::kPubKeySize + ble_key::kEciesNonceSize + kMasterSize + ble_key::kGcmTagSize;
// sk cifrada en reposo: salt(16) || nonce(12) || ct(32) || tag(16)
constexpr size_t kSkBlobSize = 16 + 12 + 32 + 16;

using Result = encrypted_seed_store::Result;
using ProgressFn = encrypted_seed_store::ProgressFn;

inline void buildPath(const uint8_t vaultId[4], char* out, size_t n) {
  snprintf(out, n, "/K2F-%02X%02X%02X%02X.k2f",
           vaultId[0], vaultId[1], vaultId[2], vaultId[3]);
}

// ---- sk del Core2, cifrada en reposo con PIN ----

inline bool hasEncryptedSk() { return ble_key::detail::nvsHas("ksk", kSkBlobSize); }
inline bool eraseEncryptedSk() { return ble_key::detail::nvsErase("ksk"); }

inline bool saveEncryptedSk(const uint8_t sk[kMasterSize], const char* pin) {
  if (!pin || !pin[0]) return false;
  uint8_t blob[kSkBlobSize] = {};
  esp_fill_random(blob, 16);       // salt
  esp_fill_random(blob + 16, 12);  // nonce
  uint8_t kpin[32] = {};
  if (!encrypted_seed_store::pbkdf2_sha256(pin, blob, kPinIterations, kpin)) {
    encrypted_seed_store::wipe(blob, sizeof(blob));
    return false;
  }
  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  const bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kpin, 256) == 0 &&
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, kMasterSize,
          blob + 16, 12, blob, 16, sk, blob + 28, 16, blob + 60) == 0;
  mbedtls_gcm_free(&gcm);
  encrypted_seed_store::wipe(kpin, sizeof(kpin));
  if (!ok) { encrypted_seed_store::wipe(blob, sizeof(blob)); return false; }
  const bool saved = ble_key::detail::nvsWrite("ksk", blob, kSkBlobSize);
  encrypted_seed_store::wipe(blob, sizeof(blob));
  return saved;
}

inline bool loadDecryptedSk(const char* pin, uint8_t sk[kMasterSize]) {
  if (!pin || !pin[0]) return false;
  uint8_t blob[kSkBlobSize] = {};
  if (!ble_key::detail::nvsRead("ksk", blob, kSkBlobSize)) return false;
  uint8_t kpin[32] = {};
  if (!encrypted_seed_store::pbkdf2_sha256(pin, blob, kPinIterations, kpin)) {
    encrypted_seed_store::wipe(blob, sizeof(blob));
    return false;
  }
  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  const int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kpin, 256) == 0
      ? mbedtls_gcm_auth_decrypt(&gcm, kMasterSize, blob + 16, 12, blob, 16,
          blob + 60, 16, blob + 28, sk) : -1;
  mbedtls_gcm_free(&gcm);
  encrypted_seed_store::wipe(kpin, sizeof(kpin));
  encrypted_seed_store::wipe(blob, sizeof(blob));
  if (rc != 0) encrypted_seed_store::wipe(sk, kMasterSize);
  return rc == 0;
}

// ---- envolver la maestra (M5Paper, con la publica del Core2) ----

inline Result enable(const char* path, const uint8_t master[kMasterSize],
                     const uint8_t vaultId[4], const char* label,
                     const uint8_t pk[ble_key::kPubKeySize]) {
  if (SD.cardType() == CARD_NONE) return Result::no_sd;
  if (!label || !label[0] || strlen(label) > 16) return Result::invalid_file;
  if (SD.exists(path)) SD.remove(path);
  uint8_t header[kHeaderSize] = {};
  memcpy(header, "M5K2", 4);
  header[4] = kVersion;
  header[5] = static_cast<uint8_t>(strlen(label));
  memcpy(header + 6, vaultId, 4);
  memcpy(header + 42, label, strlen(label));
  uint8_t blob[kBlobSize] = {};
  size_t blobLen = 0;
  if (!ble_key::eciesEncrypt(pk, master, kMasterSize, blob, &blobLen)) {
    encrypted_seed_store::wipe(header, sizeof(header));
    return Result::crypto_error;
  }
  File f = SD.open(path, FILE_WRITE);
  const bool ok = f && f.write(header, sizeof(header)) == sizeof(header) &&
      f.write(blob, blobLen) == blobLen;
  if (f) { f.flush(); f.close(); }
  encrypted_seed_store::wipe(header, sizeof(header));
  encrypted_seed_store::wipe(blob, sizeof(blob));
  if (!ok) { SD.remove(path); return Result::io_error; }
  return Result::ok;
}

// Lee el blob ECIES del .k2f (el M5Paper lo envia tal cual al Core2).
inline bool readBlob(const char* path, uint8_t blob[kBlobSize]) {
  File f = SD.open(path, FILE_READ);
  if (!f) return false;
  uint8_t header[kHeaderSize] = {};
  if (f.read(header, kHeaderSize) != kHeaderSize || memcmp(header, "M5K2", 4) ||
      header[4] != kVersion) { f.close(); return false; }
  const bool ok = f.read(blob, kBlobSize) == kBlobSize;
  f.close();
  return ok;
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

inline bool readMeta(const char* path, uint8_t vaultId[4], char label[17]) {
  File f = SD.open(path, FILE_READ);
  if (!f) return false;
  uint8_t header[kHeaderSize] = {};
  const bool ok = f.read(header, kHeaderSize) == kHeaderSize &&
      !memcmp(header, "M5K2", 4) && header[4] == kVersion &&
      header[5] > 0 && header[5] <= 16;
  f.close();
  if (!ok) return false;
  memcpy(vaultId, header + 6, 4);
  memcpy(label, header + 42, header[5]);
  label[header[5]] = '\0';
  return true;
}

}  // namespace vault_2fa
