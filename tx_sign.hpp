#pragma once
#include <Arduino.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include "bitcoin_hd.hpp"
#include "psbt_parser.hpp"
#include <vector>

// Firma de transacciones Bitcoin (segwit v0 / P2WPKH, SIGHASH_ALL).
//
// AVISO: codigo criptografico de maxima responsabilidad. Usa ECDSA con nonce
// determinista RFC6979 (imprescindible: un nonce reutilizado filtra la clave).
// Solo para pruebas; NO USAR CON FONDOS REALES.

namespace tx_sign {

constexpr uint32_t kSighashAll = 1;

inline void sha256d(const uint8_t* data, size_t len, uint8_t out[32]) {
  uint8_t h1[32] = {};
  mbedtls_sha256_ret(data, len, h1, 0);
  mbedtls_sha256_ret(h1, 32, out, 0);
  bitcoin_hd::wipe(h1, 32);
}

// ---- RFC6979 (nonce determinista) ----
struct Rfc6979Ctx {
  const uint8_t* key;  // 32 bytes
  const uint8_t* msg;  // 32 bytes (sighash)
};

inline bool hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data,
                       size_t dataLen, uint8_t out[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md_hmac(info, key, keyLen, data, dataLen, out) == 0;
}

inline int rfc6979Rng(void* p, unsigned char* out, size_t len) {
  if (len < 32) return -1;
  Rfc6979Ctx* c = static_cast<Rfc6979Ctx*>(p);
  uint8_t V[32] = {}, K[32] = {}, tmp[32] = {}, data[97] = {};
  memset(V, 0x01, 32);
  memset(K, 0x00, 32);
  static const uint8_t kN[32] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
      0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

  auto step = [&](uint8_t prefix) -> bool {
    memcpy(data, V, 32);
    data[32] = prefix;
    memcpy(data + 33, c->key, 32);
    memcpy(data + 65, c->msg, 32);
    if (!hmacSha256(K, 32, data, 97, tmp)) return false;
    memcpy(K, tmp, 32);
    if (!hmacSha256(K, 32, V, 32, tmp)) return false;
    memcpy(V, tmp, 32);
    return true;
  };
  if (!step(0x00) || !step(0x01)) return -1;

  while (true) {
    if (!hmacSha256(K, 32, V, 32, tmp)) return -1;
    memcpy(V, tmp, 32);
    bool zero = true;
    for (int i = 0; i < 32; ++i) if (V[i]) { zero = false; break; }
    if (!zero && memcmp(V, kN, 32) < 0) {
      memcpy(out, V, 32);
      bitcoin_hd::wipe(V, 32); bitcoin_hd::wipe(K, 32);
      bitcoin_hd::wipe(tmp, 32); bitcoin_hd::wipe(data, 97);
      return 0;
    }
    uint8_t d2[33] = {};
    memcpy(d2, V, 32); d2[32] = 0x00;
    if (!hmacSha256(K, 32, d2, 33, tmp)) return -1;
    memcpy(K, tmp, 32);
    if (!hmacSha256(K, 32, V, 32, tmp)) return -1;
    memcpy(V, tmp, 32);
    bitcoin_hd::wipe(d2, 33);
  }
}

// Firma ECDSA (secp256k1) con RFC6979 + normalizacion low-S.
// priv/sighash son 32 bytes; sig es r||s (64 bytes).
inline bool sign(const uint8_t priv[32], const uint8_t sighash[32], uint8_t sig[64]) {
  mbedtls_ecp_group group; mbedtls_mpi r, s, d;
  mbedtls_ecp_group_init(&group); mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s); mbedtls_mpi_init(&d);
  bool ok = false;
  if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) == 0 &&
      mbedtls_mpi_read_binary(&d, priv, 32) == 0) {
    Rfc6979Ctx ctx = {priv, sighash};
    if (mbedtls_ecdsa_sign(&group, &r, &s, &d, sighash, 32, rfc6979Rng, &ctx) == 0) {
      mbedtls_mpi halfN; mbedtls_mpi_init(&halfN);
      mbedtls_mpi_copy(&halfN, &group.N);
      mbedtls_mpi_shift_r(&halfN, 1);
      if (mbedtls_mpi_cmp_mpi(&s, &halfN) > 0) mbedtls_mpi_sub_mpi(&s, &group.N, &s);
      mbedtls_mpi_free(&halfN);
      ok = mbedtls_mpi_write_binary(&r, sig, 32) == 0 &&
           mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0;
    }
  }
  mbedtls_mpi_free(&d); mbedtls_mpi_free(&s); mbedtls_mpi_free(&r);
  mbedtls_ecp_group_free(&group);
  return ok;
}

// Log de depuracion (sin secretos): imprime un buffer en hex con etiqueta.
inline void logHex(const char* label, const uint8_t* data, size_t len) {
  static const char hexc[] = "0123456789abcdef";
  Serial.printf("[SIGN] %s=", label);
  for (size_t i = 0; i < len; ++i) Serial.printf("%c%c", hexc[data[i] >> 4], hexc[data[i] & 0xF]);
  Serial.println();
}

// Declaraciones adelantadas (definidas mas abajo) usadas por testECDSARoundtrip.
inline size_t derEncode(const uint8_t r[32], const uint8_t s[32], uint8_t out[73]);
inline bool derDecode(const uint8_t* der, size_t derLen, uint8_t rs[64]);

// Descomprime una pubkey secp256k1 comprimida (33 bytes: 02/03 + X) a SEC1 sin
// comprimir (65 bytes: 04 + X + Y). Necesario porque el mbedtls de esta build
// devuelve MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE al leer el formato comprimido.
// secp256k1: p = 2^256 - 2^32 - 977 ≡ 3 (mod 4), luego sqrt(a) = a^((p+1)/4).
inline bool decompressPubkey(const uint8_t pub[33], uint8_t out[65]) {
  const uint8_t prefix = pub[0];
  if (prefix != 0x02 && prefix != 0x03) return false;

  mbedtls_ecp_group group;
  mbedtls_ecp_group_init(&group);
  if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) != 0) {
    mbedtls_ecp_group_free(&group); return false;
  }

  mbedtls_mpi x, alpha, temp, exp, y, y2, rem;
  mbedtls_mpi_init(&x); mbedtls_mpi_init(&alpha); mbedtls_mpi_init(&temp);
  mbedtls_mpi_init(&exp); mbedtls_mpi_init(&y); mbedtls_mpi_init(&y2);
  mbedtls_mpi_init(&rem);
  bool ok = false;
  int parity = 0;

  if (mbedtls_mpi_read_binary(&x, pub + 1, 32) != 0) goto cleanup;
  // alpha = x^3 + B mod P
  if (mbedtls_mpi_mul_mpi(&temp, &x, &x) != 0) goto cleanup;          // x^2
  if (mbedtls_mpi_mod_mpi(&temp, &temp, &group.P) != 0) goto cleanup;
  if (mbedtls_mpi_mul_mpi(&alpha, &temp, &x) != 0) goto cleanup;      // x^3
  if (mbedtls_mpi_mod_mpi(&alpha, &alpha, &group.P) != 0) goto cleanup;
  if (mbedtls_mpi_add_mpi(&alpha, &alpha, &group.B) != 0) goto cleanup;
  if (mbedtls_mpi_mod_mpi(&alpha, &alpha, &group.P) != 0) goto cleanup;
  // exp = (P + 1) / 4
  if (mbedtls_mpi_add_int(&temp, &group.P, 1) != 0) goto cleanup;
  if (mbedtls_mpi_div_int(&exp, &rem, &temp, 4) != 0) goto cleanup;
  // y = alpha^exp mod P
  if (mbedtls_mpi_exp_mod(&y, &alpha, &exp, &group.P, nullptr) != 0) goto cleanup;
  // verificar y^2 == alpha
  if (mbedtls_mpi_mul_mpi(&y2, &y, &y) != 0) goto cleanup;
  if (mbedtls_mpi_mod_mpi(&y2, &y2, &group.P) != 0) goto cleanup;
  if (mbedtls_mpi_cmp_mpi(&y2, &alpha) != 0) goto cleanup;  // x no esta en la curva
  // ajustar paridad segun el prefijo (02 = par, 03 = impar)
  parity = mbedtls_mpi_get_bit(&y, 0);
  if ((prefix == 0x02 && parity == 1) || (prefix == 0x03 && parity == 0)) {
    if (mbedtls_mpi_sub_mpi(&y, &group.P, &y) != 0) goto cleanup;
  }
  out[0] = 0x04;
  if (mbedtls_mpi_write_binary(&x, out + 1, 32) != 0) goto cleanup;
  if (mbedtls_mpi_write_binary(&y, out + 33, 32) != 0) goto cleanup;
  ok = true;

cleanup:
  mbedtls_mpi_free(&rem); mbedtls_mpi_free(&y2); mbedtls_mpi_free(&y);
  mbedtls_mpi_free(&exp); mbedtls_mpi_free(&temp); mbedtls_mpi_free(&alpha);
  mbedtls_mpi_free(&x); mbedtls_ecp_group_free(&group);
  if (!ok) { volatile uint8_t* p = out; for (size_t i = 0; i < 65; ++i) p[i] = 0; }
  return ok;
}

// Verificacion ECDSA secp256k1 (autoverificacion local tras firmar).
// Implementacion manual con aritmetica de mbedTLS:
//   w = s^-1 mod n ; u1 = e*w mod n ; u2 = r*w mod n ; R = u1*G + u2*Q
//   valida  <=>  R.x mod n == r
inline bool verify(const uint8_t pub[33], const uint8_t sighash[32],
                   const uint8_t rs[64]) {
  mbedtls_ecp_group group; mbedtls_ecp_point Q, R;
  mbedtls_mpi r, s, e, w, u1, u2, rx;
  mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&Q); mbedtls_ecp_point_init(&R);
  mbedtls_mpi_init(&r); mbedtls_mpi_init(&s); mbedtls_mpi_init(&e); mbedtls_mpi_init(&w);
  mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2); mbedtls_mpi_init(&rx);
  bool ok = false;
  const int rcLoad = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  // La pubkey comprimida (33 bytes) no la acepta este mbedtls: descomprimir antes.
  logHex("pubkey compressed", pub, 33);
  uint8_t pub65[65] = {};
  const bool decompressed = decompressPubkey(pub, pub65);
  logHex("pubkey decompressed", pub65, 65);
  const int rcQ = decompressed ? mbedtls_ecp_point_read_binary(&group, &Q, pub65, 65) : -1;
  const int rcR = mbedtls_mpi_read_binary(&r, rs, 32);
  const int rcS = mbedtls_mpi_read_binary(&s, rs + 32, 32);
  const int rcE = mbedtls_mpi_read_binary(&e, sighash, 32);
  const bool rRange = mbedtls_mpi_cmp_int(&r, 1) >= 0 && mbedtls_mpi_cmp_mpi(&r, &group.N) < 0;
  const bool sRange = mbedtls_mpi_cmp_int(&s, 1) >= 0 && mbedtls_mpi_cmp_mpi(&s, &group.N) < 0;
  const int rcInv = mbedtls_mpi_inv_mod(&w, &s, &group.N);
  Serial.printf("[ECDSA] rc: load=%d readQ=%d readR=%d readS=%d readE=%d rRange=%d sRange=%d inv=%d\n",
                rcLoad, rcQ, rcR, rcS, rcE, rRange ? 1 : 0, sRange ? 1 : 0, rcInv);
  if (rcLoad == 0 && rcQ == 0 && rcR == 0 && rcS == 0 && rcE == 0 &&
      rRange && sRange && rcInv == 0) {
    mbedtls_mpi_mul_mpi(&u1, &e, &w); mbedtls_mpi_mod_mpi(&u1, &u1, &group.N);
    mbedtls_mpi_mul_mpi(&u2, &r, &w); mbedtls_mpi_mod_mpi(&u2, &u2, &group.N);
    const int rcMuladd = mbedtls_ecp_muladd(&group, &R, &u1, &group.G, &u2, &Q);
    Serial.printf("[ECDSA] muladd rc=%d\n", rcMuladd);
    if (rcMuladd == 0) {
      mbedtls_mpi_mod_mpi(&rx, &R.X, &group.N);
      const int cmp = mbedtls_mpi_cmp_mpi(&rx, &r);
      Serial.printf("[ECDSA] cmp(rx,r)=%d\n", cmp);
      ok = cmp == 0;
    }
  }
  mbedtls_mpi_free(&rx); mbedtls_mpi_free(&u2); mbedtls_mpi_free(&u1);
  mbedtls_mpi_free(&w); mbedtls_mpi_free(&e); mbedtls_mpi_free(&s); mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&R); mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&group);
  return ok;
}

// Test aislado sign -> verify (sin PSBT ni Bitcoin). Si esto falla, el problema
// esta en la capa ECDSA (formato de firma/pubkey), no en el pipeline Bitcoin.
inline bool testECDSARoundtrip() {
  static const uint8_t priv[32] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
      0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
  static const uint8_t msg[32] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
      0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
      0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};
  uint8_t pub[33] = {};
  mbedtls_ecp_group group; mbedtls_ecp_point P; mbedtls_mpi d;
  mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&P); mbedtls_mpi_init(&d);
  size_t olen = 0;
  bool ok = false;
  if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) == 0 &&
      mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
      mbedtls_ecp_mul(&group, &P, &d, &group.G, nullptr, nullptr) == 0 &&
      mbedtls_ecp_point_write_binary(&group, &P, MBEDTLS_ECP_PF_COMPRESSED,
                                     &olen, pub, 33) == 0 && olen == 33) {
    uint8_t rs[64] = {};
    if (sign(priv, msg, rs)) {
      ok = verify(pub, msg, rs);
      Serial.printf("[ECDSA] native verify=%s\n", ok ? "OK" : "FAILED");
      // DER encode -> parse -> verify de nuevo (valida el encoder DER).
      uint8_t der[73] = {};
      const size_t derLen = derEncode(rs, rs + 32, der);
      Serial.printf("[ECDSA] DER length=%u\n", static_cast<unsigned>(derLen));
      logHex("DER", der, derLen);
      uint8_t rs2[64] = {};
      const bool derOk = derDecode(der, derLen, rs2) && verify(pub, msg, rs2);
      Serial.printf("[ECDSA] DER roundtrip verify=%s\n", derOk ? "OK" : "FAILED");
      ok = ok && derOk;
      bitcoin_hd::wipe(rs2, 64); bitcoin_hd::wipe(der, 73);
    }
    bitcoin_hd::wipe(rs, 64);
  }
  mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&P); mbedtls_ecp_group_free(&group);
  bitcoin_hd::wipe(pub, 33);
  return ok;
}

// Deriva la clave privada a partir de la semilla usando la ruta BIP32 completa.
// El fingerprint del PSBT es el de la clave MAESTRA (m), y la ruta es la completa
// (p.ej. m/84'/0'/0'/1/0), como hace BlueWallet.
inline bool deriveKey(const uint16_t* words, size_t count,
                      const uint8_t fpr[4], const std::vector<uint32_t>& path,
                      const char* passphrase, uint8_t outKey[32], uint8_t outPub[33],
                      bool verbose = true) {
  uint8_t seed[64] = {};
  bitcoin_hd::Node master = {}, node = {};
  uint8_t masterFpr[4] = {};
  if (!bitcoin_hd::mnemonic_seed(words, count, seed, passphrase) ||
      !bitcoin_hd::master(seed, master)) {
    bitcoin_hd::wipe(seed, sizeof(seed)); return false;
  }
  bitcoin_hd::fingerprint(master, masterFpr);
  if (memcmp(masterFpr, fpr, 4) != 0) {
    // En la busqueda de seeds del Vault esto es normal (se prueban varias seeds);
    // solo se loggea si lo pide el llamante (single-sig).
    if (verbose) {
      Serial.printf("[SIGN] FPR mismatch (master): PSBT=%02X%02X%02X%02X semilla=%02X%02X%02X%02X pass=%s\n",
                    fpr[0], fpr[1], fpr[2], fpr[3], masterFpr[0], masterFpr[1],
                    masterFpr[2], masterFpr[3],
                    (passphrase && passphrase[0]) ? "SI" : "NO");
    }
    bitcoin_hd::wipe(seed, sizeof(seed)); bitcoin_hd::wipe(&master, sizeof(master));
    bitcoin_hd::wipe(masterFpr, 4);
    return false;
  }
  node = master;
  bool ok = true;
  for (uint32_t idx : path) {
    bitcoin_hd::Node next = {};
    if (idx & 0x80000000UL) ok = ok && bitcoin_hd::derive_hardened(node, idx & 0x7fffffffUL, next);
    else ok = ok && bitcoin_hd::derive_normal(node, idx, next);
    bitcoin_hd::wipe(&node, sizeof(node));
    node = next;
    if (!ok) break;
  }
  if (ok) {
    memcpy(outKey, node.key, 32);
    ok = bitcoin_hd::public_key(node, outPub);
  }
  bitcoin_hd::wipe(seed, sizeof(seed)); bitcoin_hd::wipe(&master, sizeof(master));
  bitcoin_hd::wipe(&node, sizeof(node)); bitcoin_hd::wipe(masterFpr, 4);
  return ok;
}

// Sighash BIP143 (segwit v0) con SIGHASH_ALL. scriptCode debe ser el script
// serializado (para P2WPKH: 0x1976a914{20}88ac).
inline bool sighashSegwit(const psbt::ParsedTx& tx, size_t inputIndex,
                          const uint8_t* scriptCode, size_t scriptCodeLen,
                          uint64_t amount, uint8_t out[32]) {
  if (inputIndex >= tx.inputs.size()) return false;
  std::vector<uint8_t> buf;
  uint8_t h[32] = {};

  buf.reserve(tx.inputs.size() * 36 + tx.outputs.size() * 100 + 200);
  for (const auto& in : tx.inputs) {
    buf.insert(buf.end(), in.prevTxid, in.prevTxid + 32);
    for (int b = 0; b < 4; ++b) buf.push_back((in.prevVout >> (8 * b)) & 0xff);
  }
  sha256d(buf.data(), buf.size(), h);
  uint8_t hashPrevouts[32]; memcpy(hashPrevouts, h, 32);

  buf.clear();
  for (const auto& in : tx.inputs)
    for (int b = 0; b < 4; ++b) buf.push_back((in.sequence >> (8 * b)) & 0xff);
  sha256d(buf.data(), buf.size(), h);
  uint8_t hashSequence[32]; memcpy(hashSequence, h, 32);

  buf.clear();
  for (const auto& o : tx.outputs) {
    for (int b = 0; b < 8; ++b) buf.push_back((o.value >> (8 * b)) & 0xff);
    if (o.scriptLen < 0xfd) buf.push_back(o.scriptLen);
    else { buf.push_back(0xfd); buf.push_back(o.scriptLen & 0xff); buf.push_back(o.scriptLen >> 8); }
    buf.insert(buf.end(), o.script, o.script + o.scriptLen);
  }
  sha256d(buf.data(), buf.size(), h);
  uint8_t hashOutputs[32]; memcpy(hashOutputs, h, 32);

  buf.clear();
  for (int b = 0; b < 4; ++b) buf.push_back((tx.version >> (8 * b)) & 0xff);
  buf.insert(buf.end(), hashPrevouts, hashPrevouts + 32);
  buf.insert(buf.end(), hashSequence, hashSequence + 32);
  const auto& in = tx.inputs[inputIndex];
  buf.insert(buf.end(), in.prevTxid, in.prevTxid + 32);
  for (int b = 0; b < 4; ++b) buf.push_back((in.prevVout >> (8 * b)) & 0xff);
  buf.push_back(static_cast<uint8_t>(scriptCodeLen));
  buf.insert(buf.end(), scriptCode, scriptCode + scriptCodeLen);
  for (int b = 0; b < 8; ++b) buf.push_back((amount >> (8 * b)) & 0xff);
  for (int b = 0; b < 4; ++b) buf.push_back((in.sequence >> (8 * b)) & 0xff);
  buf.insert(buf.end(), hashOutputs, hashOutputs + 32);
  for (int b = 0; b < 4; ++b) buf.push_back((tx.locktime >> (8 * b)) & 0xff);
  buf.push_back(0x01); buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00);

  logHex("hashPrevouts", hashPrevouts, 32);
  logHex("hashSequence", hashSequence, 32);
  logHex("hashOutputs", hashOutputs, 32);
  logHex("preimage", buf.data(), buf.size());
  sha256d(buf.data(), buf.size(), out);
  logHex("sighash", out, 32);
  bitcoin_hd::wipe(hashPrevouts, 32); bitcoin_hd::wipe(hashSequence, 32);
  bitcoin_hd::wipe(hashOutputs, 32); bitcoin_hd::wipe(h, 32);
  return true;
}

// Determina el proposito (44/49/84/86) a partir del scriptPubKey.
inline bool scriptPurpose(const uint8_t* script, size_t len, uint32_t& purpose) {
  if (len == 22 && script[0] == 0x00 && script[1] == 0x14) { purpose = 84; return true; }  // P2WPKH
  if (len == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
      script[23] == 0x88 && script[24] == 0xac) { purpose = 44; return true; }           // P2PKH
  if (len == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
    purpose = 49; return true;                                                           // P2SH
  }
  if (len == 34 && script[0] == 0x51 && script[1] == 0x20) { purpose = 86; return true; }  // P2TR
  return false;
}

// Direccion de una clave publica comprimida segun el proposito.
inline String pubkeyToAddress(const uint8_t pub[33], uint32_t purpose) {
  uint8_t kh[20] = {}, redeem[22] = {}, rh[20] = {};
  bitcoin_address::hash160(pub, 33, kh);
  String r;
  if (purpose == 84) r = bitcoin_address::segwit_address(0, kh, 20);
  else if (purpose == 44) r = bitcoin_address::base58_address(0, kh);
  else if (purpose == 49) {
    redeem[0] = 0x00; redeem[1] = 0x14; memcpy(redeem + 2, kh, 20);
    bitcoin_address::hash160(redeem, 22, rh);
    r = bitcoin_address::base58_address(5, rh);
  }
  bitcoin_hd::wipe(kh, 20); bitcoin_hd::wipe(redeem, 22); bitcoin_hd::wipe(rh, 20);
  return r;
}

// Comprueba si una salida pertenece a nuestra semilla. Si la salida trae ruta
// de derivacion (clave 0x02) se usa esa ruta; si no (Sparrow no marca el cambio)
// se busca la direccion en el espacio de derivacion de la wallet.
inline bool findKeyByAddress(const uint16_t* words, size_t count, uint32_t purpose,
                             const uint8_t* pubkeyHash20, const char* passphrase,
                             uint8_t outKey[32], uint8_t outPub[33],
                             bool changeOnly = false, uint32_t gapLimit = 100);

inline bool outputMatchesWallet(const psbt::TxOutput& out, const uint16_t* words,
                                size_t count, const char* passphrase, bool& isOurs) {
  isOurs = false;
  uint32_t purpose = 0;
  if (!scriptPurpose(out.script, out.scriptLen, purpose)) return false;
  uint8_t key[32] = {}, pub[33] = {};
  bool ok = false;
  if (out.hasDerivation) {
    ok = deriveKey(words, count, out.derivFpr, out.derivPath, passphrase, key, pub);
  } else if (purpose == 84 && out.scriptLen == 22 &&
             out.script[0] == 0x00 && out.script[1] == 0x14) {
    ok = findKeyByAddress(words, count, 84, out.script + 2, passphrase, key, pub, true, 20);
  } else if (purpose == 44 && out.scriptLen == 25 &&
             out.script[0] == 0x76 && out.script[1] == 0xa9 && out.script[2] == 0x14) {
    ok = findKeyByAddress(words, count, 44, out.script + 3, passphrase, key, pub, true, 20);
  }
  if (!ok) { bitcoin_hd::wipe(key, 32); return false; }
  const String derived = pubkeyToAddress(pub, purpose);
  bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(pub, 33);
  isOurs = derived.length() > 0 && derived == out.address;
  return derived.length() > 0;
}

// ---- Finalizacion y serializacion de la transaccion firmada ----

inline size_t derEncode(const uint8_t r[32], const uint8_t s[32], uint8_t out[73]) {
  auto enc = [](const uint8_t* v, uint8_t* o) -> size_t {
    size_t start = 0;
    while (start < 31 && v[start] == 0) ++start;
    const size_t len = 32 - start;
    if (v[start] & 0x80) { o[0] = 0x00; memcpy(o + 1, v + start, len); return len + 1; }
    memcpy(o, v + start, len);
    return len;
  };
  uint8_t rb[33] = {}, sb[33] = {};
  const size_t rl = enc(r, rb), sl = enc(s, sb);
  const size_t total = 2 + rl + 2 + sl;
  size_t idx = 0;
  out[idx++] = 0x30;
  out[idx++] = static_cast<uint8_t>(total);
  out[idx++] = 0x02; out[idx++] = static_cast<uint8_t>(rl); memcpy(out + idx, rb, rl); idx += rl;
  out[idx++] = 0x02; out[idx++] = static_cast<uint8_t>(sl); memcpy(out + idx, sb, sl); idx += sl;
  return idx;
}

// Parsea una firma DER (sin byte de sighash) de vuelta a r||s compacto (64 bytes).
inline bool derDecode(const uint8_t* der, size_t derLen, uint8_t rs[64]) {
  size_t p = 0;
  if (derLen < 9 || der[p++] != 0x30) return false;
  size_t seqLen;
  if (der[p] == 0x81) { seqLen = der[p + 1]; p += 2; }
  else if (der[p] < 0x80) { seqLen = der[p]; p += 1; }
  else return false;
  if (p + seqLen != derLen) return false;
  if (der[p++] != 0x02) return false;
  size_t rlen = der[p++];
  if (rlen == 0 || rlen > 33 || p + rlen > derLen) return false;
  size_t rstart = (der[p] == 0x00 && rlen > 1) ? 1 : 0;
  size_t rbytes = rlen - rstart;
  if (rbytes > 32) return false;
  memset(rs, 0, 32);
  memcpy(rs + 32 - rbytes, der + p + rstart, rbytes);
  p += rlen;
  if (der[p++] != 0x02) return false;
  size_t slen = der[p++];
  if (slen == 0 || slen > 33 || p + slen > derLen) return false;
  size_t sstart = (der[p] == 0x00 && slen > 1) ? 1 : 0;
  size_t sbytes = slen - sstart;
  if (sbytes > 32) return false;
  memset(rs + 32, 0, 32);
  memcpy(rs + 32 + 32 - sbytes, der + p + sstart, sbytes);
  return true;
}

inline void pushVarint(std::vector<uint8_t>& o, uint64_t v) {
  if (v < 0xfd) { o.push_back(static_cast<uint8_t>(v)); }
  else if (v <= 0xffff) {
    o.push_back(0xfd); o.push_back(v & 0xff); o.push_back((v >> 8) & 0xff);
  } else {
    o.push_back(0xfe); for (int b = 0; b < 4; ++b) o.push_back((v >> (8 * b)) & 0xff);
  }
}

struct InputSig {
  uint8_t der[73] = {};
  size_t derLen = 0;
  uint8_t pub[33] = {};
};

inline void serializeSignedTx(const psbt::ParsedTx& tx, const std::vector<InputSig>& sigs,
                              std::vector<uint8_t>& out) {
  out.clear();
  for (int b = 0; b < 4; ++b) out.push_back((tx.version >> (8 * b)) & 0xff);
  out.push_back(0x00); out.push_back(0x01);  // segwit marker + flag
  pushVarint(out, tx.inputs.size());
  for (const auto& in : tx.inputs) {
    out.insert(out.end(), in.prevTxid, in.prevTxid + 32);
    for (int b = 0; b < 4; ++b) out.push_back((in.prevVout >> (8 * b)) & 0xff);
    out.push_back(0x00);  // scriptSig vacio
    for (int b = 0; b < 4; ++b) out.push_back((in.sequence >> (8 * b)) & 0xff);
  }
  pushVarint(out, tx.outputs.size());
  for (const auto& o : tx.outputs) {
    for (int b = 0; b < 8; ++b) out.push_back((o.value >> (8 * b)) & 0xff);
    pushVarint(out, o.scriptLen);
    out.insert(out.end(), o.script, o.script + o.scriptLen);
  }
  for (const auto& s : sigs) {
    out.push_back(0x02);  // 2 items del witness
    pushVarint(out, s.derLen);
    out.insert(out.end(), s.der, s.der + s.derLen);
    pushVarint(out, 33);
    out.insert(out.end(), s.pub, s.pub + 33);
  }
  for (int b = 0; b < 4; ++b) out.push_back((tx.locktime >> (8 * b)) & 0xff);
}

// Serializa la transaccion SIN witness (version + vin + vout + locktime),
// como se guarda en el campo global de un PSBT.
inline void serializeUnsignedTx(const psbt::ParsedTx& tx, std::vector<uint8_t>& out) {
  out.clear();
  for (int b = 0; b < 4; ++b) out.push_back((tx.version >> (8 * b)) & 0xff);
  pushVarint(out, tx.inputs.size());
  for (const auto& in : tx.inputs) {
    out.insert(out.end(), in.prevTxid, in.prevTxid + 32);
    for (int b = 0; b < 4; ++b) out.push_back((in.prevVout >> (8 * b)) & 0xff);
    out.push_back(0x00);  // scriptSig vacio
    for (int b = 0; b < 4; ++b) out.push_back((in.sequence >> (8 * b)) & 0xff);
  }
  pushVarint(out, tx.outputs.size());
  for (const auto& o : tx.outputs) {
    for (int b = 0; b < 8; ++b) out.push_back((o.value >> (8 * b)) & 0xff);
    pushVarint(out, o.scriptLen);
    out.insert(out.end(), o.script, o.script + o.scriptLen);
  }
  for (int b = 0; b < 4; ++b) out.push_back((tx.locktime >> (8 * b)) & 0xff);
}

// Construye un PSBT finalizado (BIP174) con el witness de cada entrada.
// Es el formato que BlueWallet reconoce y puede emitir.
inline void buildFinalizedPsbt(const psbt::ParsedTx& tx, const std::vector<InputSig>& sigs,
                               std::vector<uint8_t>& out) {
  std::vector<uint8_t> unsignedTx;
  serializeUnsignedTx(tx, unsignedTx);
  out.clear();
  const uint8_t magic[5] = {0x70, 0x73, 0x62, 0x74, 0xff};
  out.insert(out.end(), magic, magic + 5);
  out.push_back(0x01); out.push_back(0x00);  // global map: key 0x00 = unsigned tx
  pushVarint(out, unsignedTx.size());
  out.insert(out.end(), unsignedTx.begin(), unsignedTx.end());
  out.push_back(0x00);
  for (const auto& s : sigs) {
    std::vector<uint8_t> witness;
    pushVarint(witness, 2);
    pushVarint(witness, s.derLen);
    witness.insert(witness.end(), s.der, s.der + s.derLen);
    pushVarint(witness, 33);
    witness.insert(witness.end(), s.pub, s.pub + 33);
    out.push_back(0x01); out.push_back(0x08);  // input map: key 0x08 = final witness
    pushVarint(out, witness.size());
    out.insert(out.end(), witness.begin(), witness.end());
    out.push_back(0x00);
  }
  for (size_t i = 0; i < tx.outputs.size(); ++i) out.push_back(0x00);  // output maps vacios
}

// Busca la clave privada cuya direccion coincide con pubkeyHash20 recorriendo el
// espacio de derivacion de la wallet. Si changeOnly es true, solo recorre la rama
// de cambio (m/.../1/*), que es donde vive el cambio.
inline bool findKeyByAddress(const uint16_t* words, size_t count, uint32_t purpose,
                             const uint8_t* pubkeyHash20, const char* passphrase,
                             uint8_t outKey[32], uint8_t outPub[33],
                             bool changeOnly, uint32_t gapLimit) {
  bitcoin_hd::Node account = {};
  if (!bitcoin_hd::account_node(words, count, purpose, account, passphrase)) return false;
  const uint8_t chStart = changeOnly ? 1 : 0;
  for (uint8_t ch = chStart; ch <= 1; ++ch) {
    bitcoin_hd::Node branch = {};
    if (!bitcoin_hd::derive_normal(account, ch, branch)) continue;
    for (uint32_t idx = 0; idx < gapLimit; ++idx) {
      bitcoin_hd::Node child = {};
      if (!bitcoin_hd::derive_normal(branch, idx, child)) {
        bitcoin_hd::wipe(&child, sizeof(child)); continue;
      }
      uint8_t pub[33] = {}, kh[20] = {};
      bool match = false;
      if (bitcoin_hd::public_key(child, pub)) {
        bitcoin_address::hash160(pub, 33, kh);
        match = !memcmp(kh, pubkeyHash20, 20);
      }
      if (match) {
        memcpy(outKey, child.key, 32); memcpy(outPub, pub, 33);
        Serial.printf("[SIGN] encontrada change=%u index=%u\n", ch, static_cast<unsigned>(idx));
        bitcoin_hd::wipe(&child, sizeof(child)); bitcoin_hd::wipe(&branch, sizeof(branch));
        bitcoin_hd::wipe(&account, sizeof(account));
        bitcoin_hd::wipe(pub, 33); bitcoin_hd::wipe(kh, 20);
        return true;
      }
      bitcoin_hd::wipe(&child, sizeof(child)); bitcoin_hd::wipe(pub, 33); bitcoin_hd::wipe(kh, 20);
    }
    bitcoin_hd::wipe(&branch, sizeof(branch));
  }
  Serial.printf("[SIGN] NO encontrada (changeOnly=%d gap=%u)\n", changeOnly,
                static_cast<unsigned>(gapLimit));
  bitcoin_hd::wipe(&account, sizeof(account));
  return false;
}

// Firma todos los inputs (solo P2WPKH / purpose 84, SIGHASH_ALL) y serializa la
// transaccion segwit final en signedTx.
inline bool signSegwitP2wpkh(psbt::ParsedTx& tx, const uint16_t* words, size_t count,
                             const char* passphrase, std::vector<uint8_t>& signedTx,
                             std::vector<uint8_t>* finalizedPsbt = nullptr) {
  std::vector<InputSig> sigs(tx.inputs.size());
  for (size_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& in = tx.inputs[i];
    // Identificacion inequivoca del tipo de input (desde el UTXO, no desde los
    // outputs de la nueva transaccion).
    if (in.utxoScriptLen != 22 || in.utxoScript[0] != 0x00 || in.utxoScript[1] != 0x14) {
      Serial.printf("[SIGN] input=%u type=UNKNOWN\n", static_cast<unsigned>(i));
      return false;
    }
    if (!in.amountKnown) return false;
    Serial.printf("[SIGN] input=%u\n[SIGN] type=P2WPKH\n", static_cast<unsigned>(i));
    logHex("prev_txid", in.prevTxid, 32);
    Serial.printf("[SIGN] prev_vout=%u\n", static_cast<unsigned>(in.prevVout));
    Serial.printf("[SIGN] amount_sat=%llu\n",
                  static_cast<unsigned long long>(in.amount));
    logHex("scriptPubKey", in.utxoScript, in.utxoScriptLen);
    Serial.printf("[SIGN] sequence=%u\n", static_cast<unsigned>(in.sequence));
    Serial.printf("[SIGN] version=%u\n", static_cast<unsigned>(tx.version));
    Serial.printf("[SIGN] locktime=%u\n", static_cast<unsigned>(tx.locktime));
    Serial.printf("[SIGN] sighash_type=01\n");

    uint8_t key[32] = {}, pub[33] = {};
    bool haveKey = false;
    if (in.hasDerivation) {
      haveKey = deriveKey(words, count, in.derivFpr, in.derivPath, passphrase, key, pub);
    } else {
      // Sin ruta BIP32: buscar la direccion en el espacio de derivacion.
      haveKey = findKeyByAddress(words, count, 84, in.utxoScript + 2, passphrase, key, pub);
    }
    if (!haveKey) { bitcoin_hd::wipe(key, 32); return false; }

    // Verificar que HASH160(pubkey derivada) == witness program del UTXO.
    logHex("derived_pubkey", pub, 33);
    uint8_t pubHash[20] = {};
    bitcoin_address::hash160(pub, 33, pubHash);
    logHex("pubkey_hash", pubHash, 20);
    logHex("witness_hash", in.utxoScript + 2, 20);
    if (memcmp(pubHash, in.utxoScript + 2, 20) != 0) {
      Serial.println("[SIGN] PUBKEY HASH MISMATCH");
      bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(pubHash, 20);
      return false;
    }
    bitcoin_hd::wipe(pubHash, 20);

    // scriptCode P2WPKH: 76a914{20-byte-pubkey-hash}88ac (25 bytes). NO usar el
    // witness program 0014... directamente como scriptCode.
    uint8_t scriptCode[25] = {};
    scriptCode[0] = 0x76; scriptCode[1] = 0xa9; scriptCode[2] = 0x14;
    memcpy(scriptCode + 3, in.utxoScript + 2, 20);
    scriptCode[23] = 0x88; scriptCode[24] = 0xac;
    logHex("scriptCode", scriptCode, 25);

    uint8_t sighash[32] = {};
    if (!sighashSegwit(tx, i, scriptCode, 25, in.amount, sighash)) {
      bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(scriptCode, 25); return false;
    }
    uint8_t rs[64] = {};
    if (!sign(key, sighash, rs)) {
      bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(sighash, 32); bitcoin_hd::wipe(rs, 64);
      return false;
    }
    // La firma nativa de sign() es r||s compacto (64 bytes), sin sighash byte.
    Serial.println("[ECDSA] raw_format=COMPACT64");
    Serial.println("[ECDSA] raw_signature_len=64");
    logHex("raw_signature", rs, 64);

    // Autoverificacion obligatoria antes de generar la TX final (formato nativo).
    const bool nativeVerify = verify(pub, sighash, rs);
    Serial.printf("[ECDSA] native verify=%s\n", nativeVerify ? "OK" : "FAILED");

    // DER encode -> parse -> verify de nuevo (valida el encoder DER).
    sigs[i].derLen = derEncode(rs, rs + 32, sigs[i].der);
    Serial.printf("[ECDSA] DER length=%u\n", static_cast<unsigned>(sigs[i].derLen));
    logHex("DER", sigs[i].der, sigs[i].derLen);
    uint8_t rs2[64] = {};
    const bool derVerify = derDecode(sigs[i].der, sigs[i].derLen, rs2) &&
                           verify(pub, sighash, rs2);
    Serial.printf("[ECDSA] DER roundtrip verify=%s\n", derVerify ? "OK" : "FAILED");
    bitcoin_hd::wipe(rs2, 64);

    if (!nativeVerify || !derVerify) {
      Serial.println("[SIGN] SELF VERIFY FAILED");
      bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(sighash, 32); bitcoin_hd::wipe(rs, 64);
      bitcoin_hd::wipe(scriptCode, 25);
      return false;
    }
    Serial.println("[SIGN] SELF VERIFY OK");
    logHex("pubkey", pub, 33);
    sigs[i].der[sigs[i].derLen++] = kSighashAll;  // añadir 0x01 (SIGHASH_ALL)
    logHex("DER_signature", sigs[i].der, sigs[i].derLen);
    memcpy(sigs[i].pub, pub, 33);
    bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(sighash, 32); bitcoin_hd::wipe(rs, 64);
    bitcoin_hd::wipe(scriptCode, 25);
  }
  serializeSignedTx(tx, sigs, signedTx);
  if (finalizedPsbt) buildFinalizedPsbt(tx, sigs, *finalizedPsbt);
  for (auto& s : sigs) bitcoin_hd::wipe(&s, sizeof(s));
  return !signedTx.empty();
}

// Self-test: RFC6979 + ECDSA secp256k1 con el vector del RFC 6979 (SHA-256,
// "sample"). Valida la generacion de nonce determinista y la firma.
inline bool self_test() {
  static const uint8_t key[32] = {
      0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57,
      0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
      0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21};
  static const uint8_t hash[32] = {  // SHA256("sample")
      0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1, 0xD6,
      0x94, 0xF4, 0x1F, 0xC7, 0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
      0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF};
  static const uint8_t expectR[32] = {
      0x43, 0x23, 0x10, 0xE3, 0x2C, 0xB8, 0x0E, 0xB6, 0x50, 0x3A, 0x26, 0xCE,
      0x83, 0xCC, 0x16, 0x5C, 0x78, 0x3B, 0x87, 0x08, 0x45, 0xFB, 0x8A, 0xAD,
      0x6D, 0x97, 0x08, 0x89, 0xFC, 0xD7, 0xA6, 0xC8};
  static const uint8_t expectS[32] = {
      0x53, 0x01, 0x28, 0xB6, 0xB8, 0x1C, 0x54, 0x88, 0x74, 0xA6, 0x30, 0x5D,
      0x93, 0xED, 0x07, 0x1C, 0xA6, 0xE0, 0x50, 0x74, 0xD8, 0x58, 0x63, 0xD4,
      0x05, 0x6C, 0xE8, 0x9B, 0x02, 0xBF, 0xAB, 0x69};
  uint8_t sig[64] = {};
  const bool ok = sign(key, hash, sig);
  const bool match = memcmp(sig, expectR, 32) == 0 && memcmp(sig + 32, expectS, 32) == 0;
  Serial.printf("[ECDSA] RFC6979 sign=%s vector_match=%s\n",
                ok ? "OK" : "FAIL", match ? "OK" : "FAIL");
  bitcoin_hd::wipe(sig, 64);
  return ok && match && testECDSARoundtrip();
}

}  // namespace tx_sign
