#pragma once
#include <Arduino.h>
#include <string.h>
#include "ble_key.hpp"

// Protocolo de provisioning BLE: M5Paper (cliente/central) -> M5Stick
// (servidor/peripheral) en modo "IMPORT SEED".
//
// Ver PROTOCOLO_M5STICK.md para la especificacion completa.
//
//   - El M5Stick anuncia con kDeviceName y expone su clave publica (READ).
//   - El M5Paper cifra la seed (mnemonic + fingerprint) con ECIES sobre
//     secp256k1 usando esa clave publica.
//   - El M5Stick descifra, muestra "IMPORT SEED? FPR ..." y el usuario confirma
//     fisicamente (HOLD CENTER); luego notifica el estado.
//
// La seed nunca viaja en claro.

namespace ble_provision {

constexpr char kDeviceName[] = "M5Stick-Signer";
constexpr char kServiceUUID[] = "e5b20001-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kPubKeyUUID[]  = "e5b20002-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kReqUUID[]     = "e5b20003-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kStatusUUID[]  = "e5b20004-7a1e-4b9c-8d2f-3c6b1a4d0001";

constexpr uint32_t kTimeoutMs = 30000;

constexpr size_t kMaxWords = 24;
// payload en claro = count(1) || word_idx LE(count*2) || fingerprint(4)
constexpr size_t kPayloadSize = 1 + kMaxWords * 2 + 4;  // 53
// blob ECIES = E(65) || nonce(12) || ct || tag(16)
constexpr size_t kBlobSize =
    ble_key::kPubKeySize + ble_key::kEciesNonceSize + kPayloadSize + ble_key::kGcmTagSize;

// Estados notificados por el M5Stick en PROV_STATUS (1 byte).
enum Status : uint8_t {
  kIdle = 0,
  kRequested = 1,
  kAccepted = 2,
  kDenied = 3,
  kError = 4,
};

// Construye el payload en claro. Devuelve la longitud (0 si count invalido).
inline size_t buildPayload(const uint16_t* words, uint8_t count,
                           const uint8_t fingerprint[4], uint8_t out[kPayloadSize]) {
  if ((count != 12 && count != 24) || !words) return 0;
  out[0] = count;
  for (uint8_t i = 0; i < count; ++i) {
    out[1 + i * 2] = static_cast<uint8_t>(words[i]);
    out[2 + i * 2] = static_cast<uint8_t>(words[i] >> 8);
  }
  memcpy(out + 1 + count * 2, fingerprint, 4);
  return 1 + count * 2 + 4;
}

// Tag de dominio de separacion para el ECDH de provisioning.
inline constexpr const char* kEcdhTag() { return "m5-stick-provision-v1"; }

// Cifra el payload con la clave publica del M5Stick.
// blob = E(65) || nonce(12) || ct || tag(16).
inline bool encrypt(const uint8_t pk[ble_key::kPubKeySize], const uint8_t* plain,
                    size_t plainLen, uint8_t blob[kBlobSize], size_t* blobLen) {
  uint8_t e[ble_key::kKeySize], E[ble_key::kPubKeySize], K[ble_key::kKeySize];
  if (!ble_key::generateKeyPair(e, E)) return false;
  if (!ble_key::deriveEcdhKey(e, pk, kEcdhTag(), K)) {
    ble_key::wipe(e, sizeof(e)); ble_key::wipe(E, sizeof(E)); return false;
  }
  memcpy(blob, E, ble_key::kPubKeySize);
  size_t olen = 0;
  const bool ok = ble_key::aesGcmEncrypt(K, plain, plainLen,
                                         blob + ble_key::kPubKeySize, &olen);
  ble_key::wipe(e, sizeof(e)); ble_key::wipe(E, sizeof(E)); ble_key::wipe(K, sizeof(K));
  if (ok) *blobLen = ble_key::kPubKeySize + olen;
  return ok;
}

// Descifra un blob con la privada propia (lado M5Stick).
inline bool decrypt(const uint8_t sk[ble_key::kKeySize], const uint8_t* blob,
                    size_t blobLen, uint8_t* plain, size_t* plainLen) {
  if (blobLen < ble_key::kPubKeySize + ble_key::kEciesNonceSize + ble_key::kGcmTagSize)
    return false;
  uint8_t K[ble_key::kKeySize];
  if (!ble_key::deriveEcdhKey(sk, blob, kEcdhTag(), K)) return false;
  const bool ok = ble_key::aesGcmDecrypt(K, blob + ble_key::kPubKeySize,
                                         blobLen - ble_key::kPubKeySize,
                                         plain, plainLen);
  ble_key::wipe(K, sizeof(K));
  return ok;
}

}  // namespace ble_provision
