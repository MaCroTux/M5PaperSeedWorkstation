#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include <esp_system.h>
#include <mbedtls/md.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <string.h>

// Llave criptografica BLE compartida entre M5Paper (cliente/verificador) y
// M5Core2 (servidor/llave fisica).
//
// EMPAREJAMIENTO (sin teclear nada):
//   El Core2 guarda una privada de largo plazo P_core2 (32 bytes, NVS "kpriv").
//   Durante el emparejamiento ambos derivan un secreto de autenticacion K_pair
//   mediante ECDH sobre secp256k1:
//     M5Paper: par efimero (p_m, Q_m), envia Q_m.
//     Core2:   deriva S = p_core2 * Q_m,  K_pair = SHA256(x(S) || tag), envia Q_core2.
//     M5Paper: deriva S = p_m * Q_core2,  K_pair = SHA256(x(S) || tag).
//   K_pair jamas viaja por el aire. Un observador pasivo no puede derivarla.
//   El usuario debe confirmar fisicamente en el Core2 (ALLOW/AUTHORIZE).
//
// DESBLOQUEO (challenge/response):
//   El M5Paper genera un challenge aleatorio de 32 bytes y lo escribe en el
//   Core2; el Core2, SOLO tras pulsar ALLOW, calcula response = HMAC-SHA256(K_pair,
//   challenge) y lo notifica; el M5Paper verifica el HMAC de forma independiente.
//
// NO contiene semillas ni claves del Vault. El Core2 solo participa en la
// autenticacion.
//
// NOTA PROTOTIPO: K_pair y P_core2 se guardan en NVS en claro. En versiones
// posteriores deben cifrarse en reposo.

namespace ble_key {

constexpr size_t kKeySize = 32;
constexpr size_t kChallengeSize = 32;
constexpr size_t kResponseSize = 32;
constexpr size_t kPubKeySize = 65;  // clave publica secp256k1 SIN comprimir (0x04 || X || Y)
constexpr uint32_t kAuthTimeoutMs = 30000;

constexpr char kServiceUUID[] = "e5a10001-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kChallengeUUID[] = "e5a10002-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kResponseUUID[] = "e5a10003-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kStatusUUID[] = "e5a10004-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kDeviceInfoUUID[] = "e5a10005-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kPairPubKeyUUID[] = "e5a10006-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kPairConfirmUUID[] = "e5a1000d-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kPairStatusUUID[] = "e5a10008-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kSetPinUUID[] = "e5a10009-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kUnlockReqUUID[] = "e5a1000a-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kUnlockRespUUID[] = "e5a1000b-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kUnlockStatusUUID[] = "e5a1000c-7a1e-4b9c-8d2f-3c6b1a4d0001";
constexpr char kDeviceName[] = "M5Core2-Key";
constexpr char kDeviceInfoValue[] = "M5Core2-Key/v4";

// Estados notificados por el servidor en AUTH_STATUS (1 byte).
enum Status : uint8_t {
  kStatusIdle = 0,
  kStatusRequested = 1,
  kStatusAuthorized = 2,
  kStatusDenied = 3,
  kStatusTimeout = 4,
};

// Estados notificados por el servidor en PAIR_STATUS (1 byte).
enum PairStatus : uint8_t {
  kPairIdle = 0,
  kPairRequested = 1,
  kPairAuthorized = 2,
  kPairDenied = 3,
};

enum UnlockStatus : uint8_t {
  kUnlockIdle = 0,
  kUnlockPinRequired = 1,
  kUnlockAuthorized = 2,
  kUnlockDenied = 3,
  kUnlockPinFailed = 4,
  kUnlockWiped = 5,
};

inline void wipe(void* data, size_t size) {
  volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
  while (size--) *p++ = 0;
}

inline bool hmacSha256(const uint8_t* key, size_t keyLen,
                       const uint8_t* data, size_t dataLen,
                       uint8_t out[kResponseSize]) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  bool ok = info && mbedtls_md_setup(&ctx, info, 1) == 0 &&
            mbedtls_md_hmac_starts(&ctx, key, keyLen) == 0 &&
            mbedtls_md_hmac_update(&ctx, data, dataLen) == 0 &&
            mbedtls_md_hmac_finish(&ctx, out) == 0;
  mbedtls_md_free(&ctx);
  return ok;
}

inline bool derivePublicKey(const uint8_t priv[kKeySize], uint8_t pub[kPubKeySize]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv, kKeySize);
  if (ret == 0) ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);
  size_t olen = 0;
  if (ret == 0)
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, pub, kPubKeySize);
  if (ret != 0)
    Serial.printf("[BLEKEY] derivePublicKey failed: -0x%04x\n", static_cast<unsigned>(-ret));
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return ret == 0 && olen == kPubKeySize;
}

inline bool generateKeyPair(uint8_t priv[kKeySize], uint8_t pub[kPubKeySize]) {
  for (int i = 0; i < 8; ++i) {
    esp_fill_random(priv, kKeySize);
    if (derivePublicKey(priv, pub)) return true;
  }
  return false;
}

// K_pair = SHA256(x(ECDH(priv, theirPub)) || tag). Devuelve kpair[32].
inline bool deriveSharedKpair(const uint8_t priv[kKeySize],
                              const uint8_t theirPub[kPubKeySize],
                              uint8_t kpair[kKeySize]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_point S;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_point_init(&S);
  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv, kKeySize);
  if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Q, theirPub, kPubKeySize);
  if (ret == 0) ret = mbedtls_ecp_mul(&grp, &S, &d, &Q, NULL, NULL);
  uint8_t x[kKeySize] = {};
  if (ret == 0) ret = mbedtls_mpi_write_binary(&S.X, x, kKeySize);
  if (ret != 0)
    Serial.printf("[BLEKEY] ecdh failed: -0x%04x\n", static_cast<unsigned>(-ret));
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_point_free(&S);
  mbedtls_ecp_group_free(&grp);
  if (ret != 0) return false;

  static const uint8_t tag[] = "m5-vault-key-pairing-v1";
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, x, kKeySize);
  mbedtls_sha256_update_ret(&ctx, tag, sizeof(tag) - 1);
  mbedtls_sha256_finish_ret(&ctx, kpair);
  mbedtls_sha256_free(&ctx);
  wipe(x, sizeof(x));
  return true;
}

inline void toHex(const uint8_t* in, size_t len, char* out) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[i * 2] = hex[in[i] >> 4];
    out[i * 2 + 1] = hex[in[i] & 0xF];
  }
  out[len * 2] = '\0';
}

inline size_t fromHex(const char* hex, size_t hexLen, uint8_t* out, size_t outLen) {
  if (hexLen % 2 != 0 || hexLen / 2 > outLen) return 0;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < hexLen; i += 2) {
    const int hi = nib(hex[i]);
    const int lo = nib(hex[i + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[i / 2] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return hexLen / 2;
}

inline bool generateKey(uint8_t key[kKeySize]) {
  esp_fill_random(key, kKeySize);
  return true;
}

// ---- NVS (Preferences), espacio "blekey" ----

namespace detail {
inline bool nvsRead(const char* name, uint8_t* out, size_t len) {
  Preferences p;
  if (!p.begin("blekey", true)) return false;
  const bool ok = p.getBytesLength(name) == static_cast<size_t>(len) &&
                  p.getBytes(name, out, len) == len;
  p.end();
  return ok;
}
inline bool nvsHas(const char* name, size_t len) {
  Preferences p;
  if (!p.begin("blekey", true)) return false;
  const bool ok = p.getBytesLength(name) == static_cast<size_t>(len);
  p.end();
  return ok;
}
inline bool nvsWrite(const char* name, const uint8_t* in, size_t len) {
  Preferences p;
  if (!p.begin("blekey", false)) return false;
  const bool ok = p.putBytes(name, in, len) == len;
  p.end();
  return ok;
}
inline bool nvsErase(const char* name) {
  Preferences p;
  if (!p.begin("blekey", false)) return false;
  const bool ok = p.remove(name);
  p.end();
  return ok;
}
}  // namespace detail

// K_pair (secreto de autenticacion compartido).
inline bool hasStoredKey() { return detail::nvsHas("kpair", kKeySize); }
inline bool loadStoredKey(uint8_t key[kKeySize]) { return detail::nvsRead("kpair", key, kKeySize); }
inline bool saveStoredKey(const uint8_t key[kKeySize]) { return detail::nvsWrite("kpair", key, kKeySize); }
inline bool eraseStoredKey() { return detail::nvsErase("kpair"); }

// P_core2 (privada de largo plazo del Core2).
inline bool hasStoredPrivKey() { return detail::nvsHas("kpriv", kKeySize); }
inline bool loadStoredPrivKey(uint8_t priv[kKeySize]) { return detail::nvsRead("kpriv", priv, kKeySize); }
inline bool saveStoredPrivKey(const uint8_t priv[kKeySize]) { return detail::nvsWrite("kpriv", priv, kKeySize); }

// ---- ECIES (secp256k1) ----
// La clave maestra del vault se cifra con la clave PUBLICA del Core2 (pk), de
// modo que solo el Core2 (con su privada sk, protegida por PIN) puede abrirla.
// La clave publica va SIN comprimir (65 bytes) para evitar el fallo de
// descompresion de punto comprimido en mbedtls 2.28.

constexpr size_t kEciesNonceSize = 12;
constexpr size_t kGcmTagSize = 16;
// blob ECIES = E(65) || nonce(12) || ciphertext(N) || tag(16)

// K = SHA256(x(ECDH(priv, theirPub)) || tag)
inline bool deriveEcdhKey(const uint8_t priv[kKeySize],
                          const uint8_t theirPub[kPubKeySize],
                          const char* tag, uint8_t out[kKeySize]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_point S;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_point_init(&S);
  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv, kKeySize);
  if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Q, theirPub, kPubKeySize);
  if (ret == 0) ret = mbedtls_ecp_mul(&grp, &S, &d, &Q, NULL, NULL);
  uint8_t x[kKeySize] = {};
  if (ret == 0) ret = mbedtls_mpi_write_binary(&S.X, x, kKeySize);
  if (ret != 0)
    Serial.printf("[BLEKEY] ecdh failed: -0x%04x\n", static_cast<unsigned>(-ret));
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_point_free(&S);
  mbedtls_ecp_group_free(&grp);
  if (ret != 0) return false;
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, x, kKeySize);
  mbedtls_sha256_update_ret(&ctx, reinterpret_cast<const unsigned char*>(tag), strlen(tag));
  mbedtls_sha256_finish_ret(&ctx, out);
  mbedtls_sha256_free(&ctx);
  wipe(x, sizeof(x));
  return true;
}

// AES-256-GCM generico. out = nonce(12) || ciphertext || tag(16).
inline bool aesGcmEncrypt(const uint8_t key[kKeySize], const uint8_t* plain,
                          size_t plainLen, uint8_t* out, size_t* outLen) {
  uint8_t nonce[kEciesNonceSize];
  esp_fill_random(nonce, sizeof(nonce));
  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  const bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plainLen, nonce,
          sizeof(nonce), nullptr, 0, plain, out + sizeof(nonce),
          kGcmTagSize, out + sizeof(nonce) + plainLen) == 0;
  mbedtls_gcm_free(&gcm);
  if (ok) {
    memcpy(out, nonce, sizeof(nonce));
    *outLen = sizeof(nonce) + plainLen + kGcmTagSize;
  }
  wipe(nonce, sizeof(nonce));
  return ok;
}

inline bool aesGcmDecrypt(const uint8_t key[kKeySize], const uint8_t* in,
                          size_t inLen, uint8_t* plain, size_t* plainLen) {
  if (inLen < kEciesNonceSize + kGcmTagSize) return false;
  const size_t ctLen = inLen - kEciesNonceSize - kGcmTagSize;
  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  const int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0
      ? mbedtls_gcm_auth_decrypt(&gcm, ctLen, in, kEciesNonceSize, nullptr, 0,
          in + kEciesNonceSize + ctLen, kGcmTagSize, in + kEciesNonceSize, plain) : -1;
  mbedtls_gcm_free(&gcm);
  if (rc != 0) return false;
  *plainLen = ctLen;
  return true;
}

// Cifra con la clave publica del receptor. blob = E || nonce || ct || tag.
inline bool eciesEncrypt(const uint8_t pk[kPubKeySize], const uint8_t* plain,
                         size_t plainLen, uint8_t* blob, size_t* blobLen) {
  uint8_t e[kKeySize], E[kPubKeySize], K[kKeySize];
  if (!generateKeyPair(e, E)) return false;
  if (!deriveEcdhKey(e, pk, "m5-vault-ecies-v1", K)) {
    wipe(e, sizeof(e)); wipe(E, sizeof(E)); return false;
  }
  memcpy(blob, E, kPubKeySize);
  size_t olen = 0;
  const bool ok = aesGcmEncrypt(K, plain, plainLen, blob + kPubKeySize, &olen);
  wipe(e, sizeof(e)); wipe(E, sizeof(E)); wipe(K, sizeof(K));
  if (ok) *blobLen = kPubKeySize + olen;
  return ok;
}

// Descifra con la privada propia. blob = E || nonce || ct || tag.
inline bool eciesDecrypt(const uint8_t sk[kKeySize], const uint8_t* blob,
                         size_t blobLen, uint8_t* plain, size_t* plainLen) {
  if (blobLen < kPubKeySize + kEciesNonceSize + kGcmTagSize) return false;
  uint8_t K[kKeySize];
  if (!deriveEcdhKey(sk, blob, "m5-vault-ecies-v1", K)) return false;
  const bool ok = aesGcmDecrypt(K, blob + kPubKeySize, blobLen - kPubKeySize,
                                plain, plainLen);
  wipe(K, sizeof(K));
  return ok;
}

// pk (clave publica del Core2, NO secreta) guardada en el M5Paper.
inline bool hasStoredPk() { return detail::nvsHas("bpk", kPubKeySize); }
inline bool loadStoredPk(uint8_t pk[kPubKeySize]) { return detail::nvsRead("bpk", pk, kPubKeySize); }
inline bool saveStoredPk(const uint8_t pk[kPubKeySize]) { return detail::nvsWrite("bpk", pk, kPubKeySize); }
inline bool eraseStoredPk() { return detail::nvsErase("bpk"); }

}  // namespace ble_key
