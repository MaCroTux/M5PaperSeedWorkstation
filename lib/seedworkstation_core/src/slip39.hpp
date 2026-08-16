#pragma once
#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <string.h>
#include <vector>
#include "generated/slip39_words.h"
#include "bitcoin_hd.hpp"

// SLIP-0039 — Shamir's Secret-Sharing for Mnemonic Codes.
//
// Implementacion de un SOLO grupo (G=1, GT=1): SplitSecret(T, N, EMS) y
// RecoverSecret(T, shares). El master secret (MS) es la entropia BIP39 de 128 o
// 256 bits (16 o 32 bytes), de modo que las shares son mnemonics de 20 o 33
// palabras interoperables con Trezor/Electrum/Sparrow.
//
// Estructura de la share: id(15) ext(1) e(4) GI(4) Gt(4) g(4) I(4) t(4) ps C(30).

namespace slip39 {

constexpr uint8_t kMaxShares = 16;
constexpr uint8_t kMaxValueBytes = 32;  // 256 bits
constexpr uint8_t kMaxWords = 33;

inline void wipe(void* p, size_t n) {
  volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
  while (n--) *q++ = 0;
}

// ---- GF(256) (polinomio de Rijndael x^8+x^4+x^3+x+1) ----
inline uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
  while (b) {
    if (b & 1) r ^= a;
    b >>= 1;
    const uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1B;
  }
  return r;
}
inline uint8_t gf_pow(uint8_t base, int exp) {
  uint8_t r = 1;
  while (exp > 0) {
    if (exp & 1) r = gf_mul(r, base);
    base = gf_mul(base, base);
    exp >>= 1;
  }
  return r;
}
inline uint8_t gf_inv(uint8_t a) { return gf_pow(a, 254); }

// ---- HMAC-SHA256 ----
inline bool hmac_sha256(const uint8_t* key, size_t keyLen, const uint8_t* data,
                        size_t dataLen, uint8_t out[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md_hmac(info, key, keyLen, data, dataLen, out) == 0;
}

// ---- RS1024 ----
inline uint32_t rs1024_polymod(const std::vector<uint16_t>& values) {
  static const uint32_t GEN[10] = {0xE0E040, 0x1C1C080, 0x3838100, 0x7070200,
                                   0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48,
                                   0x21B1F890, 0x3F3F120};
  uint32_t chk = 1;
  for (uint16_t v : values) {
    const uint32_t b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10) ^ v;
    for (int i = 0; i < 10; ++i)
      if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

inline bool rs1024_verify(const char* cs, const std::vector<uint16_t>& data) {
  std::vector<uint16_t> values;
  values.reserve(strlen(cs) + data.size());
  for (const char* p = cs; *p; ++p) values.push_back(static_cast<uint8_t>(*p));
  values.insert(values.end(), data.begin(), data.end());
  return rs1024_polymod(values) == 1;
}

inline void rs1024_checksum(const char* cs, const std::vector<uint16_t>& data,
                            uint16_t out[3]) {
  std::vector<uint16_t> values;
  values.reserve(strlen(cs) + data.size() + 3);
  for (const char* p = cs; *p; ++p) values.push_back(static_cast<uint8_t>(*p));
  values.insert(values.end(), data.begin(), data.end());
  values.push_back(0); values.push_back(0); values.push_back(0);
  const uint32_t pm = rs1024_polymod(values) ^ 1;
  out[0] = (pm >> 20) & 1023;
  out[1] = (pm >> 10) & 1023;
  out[2] = pm & 1023;
}

// ---- PBKDF2-HMAC-SHA256 ----
inline void pbkdf2_sha256(const uint8_t* pw, size_t pwLen, const uint8_t* salt,
                          size_t saltLen, uint32_t iters, uint8_t* out,
                          size_t outLen) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info && mbedtls_md_setup(&ctx, info, 1) == 0) {
    mbedtls_pkcs5_pbkdf2_hmac(&ctx, pw, pwLen, salt, saltLen, iters, outLen, out);
  }
  mbedtls_md_free(&ctx);
}

// ---- Interpolacion de Lagrange (por byte) ----
inline void interpolate(uint8_t x, const uint8_t* xs, const uint8_t* const* ys,
                        uint8_t m, uint8_t n, uint8_t* out) {
  for (uint8_t k = 0; k < n; ++k) {
    uint8_t acc = 0;
    for (uint8_t i = 0; i < m; ++i) {
      uint8_t num = 1, den = 1;
      for (uint8_t j = 0; j < m; ++j) {
        if (i == j) continue;
        num = gf_mul(num, x ^ xs[j]);
        den = gf_mul(den, xs[i] ^ xs[j]);
      }
      acc ^= gf_mul(ys[i][k], gf_mul(num, gf_inv(den)));
    }
    out[k] = acc;
  }
}

// ---- Shamir split/recover ----
inline void split_secret(uint8_t threshold, uint8_t count, const uint8_t* secret,
                         uint8_t n, uint8_t out[16][32]) {
  if (threshold == 1) {
    for (uint8_t i = 0; i < count; ++i) memcpy(out[i], secret, n);
    return;
  }
  uint8_t R[32] = {}, D[32] = {}, dig[32] = {};
  esp_fill_random(R, n - 4);
  hmac_sha256(R, n - 4, secret, n, dig);
  memcpy(D, dig, 4);
  memcpy(D + 4, R, n - 4);

  uint8_t y[16][32] = {};
  for (uint8_t i = 0; i < threshold - 2; ++i) esp_fill_random(y[i], n);

  uint8_t xs[16];
  const uint8_t* ys[16];
  for (uint8_t i = 0; i < threshold - 2; ++i) { xs[i] = i; ys[i] = y[i]; }
  xs[threshold - 2] = 254; ys[threshold - 2] = D;
  xs[threshold - 1] = 255; ys[threshold - 1] = secret;

  for (uint8_t i = 0; i < threshold - 2; ++i) memcpy(out[i], y[i], n);
  for (uint8_t i = threshold - 2; i < count; ++i)
    interpolate(i, xs, ys, threshold, n, out[i]);

  wipe(R, sizeof(R)); wipe(D, sizeof(D)); wipe(dig, sizeof(dig)); wipe(y, sizeof(y));
}

inline bool recover_secret(uint8_t threshold, const uint8_t* xs,
                           const uint8_t* const* ys, uint8_t m, uint8_t n,
                           uint8_t* out) {
  if (threshold == 1) { memcpy(out, ys[0], n); return true; }
  uint8_t S[32] = {}, D[32] = {}, dig[32] = {};
  interpolate(255, xs, ys, m, n, S);
  interpolate(254, xs, ys, m, n, D);
  hmac_sha256(D + 4, n - 4, S, n, dig);
  const bool ok = memcmp(dig, D, 4) == 0;
  if (ok) memcpy(out, S, n);
  wipe(S, sizeof(S)); wipe(D, sizeof(D)); wipe(dig, sizeof(dig));
  return ok;
}

// ---- Feistel encrypt/decrypt del master secret ----
inline void feistel(uint8_t* L, uint8_t* R, uint8_t half, uint8_t round,
                    const char* passphrase, const uint8_t* saltPrefix,
                    size_t spLen, uint8_t e) {
  uint8_t pw[65];
  pw[0] = round;
  const size_t pplen = strlen(passphrase);
  memcpy(pw + 1, passphrase, pplen);

  uint8_t salt[48];
  memcpy(salt, saltPrefix, spLen);
  memcpy(salt + spLen, R, half);

  uint8_t F[32] = {};
  pbkdf2_sha256(pw, 1 + pplen, salt, spLen + half, 2500u << e, F, half);

  uint8_t newR[32];
  for (uint8_t i = 0; i < half; ++i) newR[i] = L[i] ^ F[i];
  memcpy(L, R, half);
  memcpy(R, newR, half);
  wipe(F, sizeof(F)); wipe(newR, sizeof(newR)); wipe(pw, sizeof(pw));
  wipe(salt, sizeof(salt));
}

inline void encrypt_ms(const uint8_t* ms, uint8_t n, const char* passphrase,
                       uint8_t e, uint16_t id, bool ext, uint8_t* ems) {
  const uint8_t half = n / 2;
  uint8_t L[32] = {}, R[32] = {};
  memcpy(L, ms, half);
  memcpy(R, ms + half, half);
  uint8_t sp[8]; size_t spLen = 0;
  if (!ext) { memcpy(sp, "shamir", 6); sp[6] = id >> 8; sp[7] = id & 0xFF; spLen = 8; }
  for (uint8_t i = 0; i < 4; ++i) feistel(L, R, half, i, passphrase, sp, spLen, e);
  memcpy(ems, R, half);
  memcpy(ems + half, L, half);
  wipe(L, sizeof(L)); wipe(R, sizeof(R)); wipe(sp, sizeof(sp));
}

inline void decrypt_ms(const uint8_t* ems, uint8_t n, const char* passphrase,
                       uint8_t e, uint16_t id, bool ext, uint8_t* ms) {
  const uint8_t half = n / 2;
  uint8_t L[32] = {}, R[32] = {};
  memcpy(L, ems, half);
  memcpy(R, ems + half, half);
  uint8_t sp[8]; size_t spLen = 0;
  if (!ext) { memcpy(sp, "shamir", 6); sp[6] = id >> 8; sp[7] = id & 0xFF; spLen = 8; }
  for (int i = 3; i >= 0; --i) feistel(L, R, half, static_cast<uint8_t>(i), passphrase, sp, spLen, e);
  memcpy(ms, R, half);
  memcpy(ms + half, L, half);
  wipe(L, sizeof(L)); wipe(R, sizeof(R)); wipe(sp, sizeof(sp));
}

// ---- Estructura de share decodificada ----
struct Share {
  uint16_t id = 0;
  bool ext = false;
  uint8_t e = 0;
  uint8_t groupIndex = 0;
  uint8_t groupThreshold = 0;  // GT (real, 1..16)
  uint8_t groupCount = 0;      // G (real)
  uint8_t memberIndex = 0;
  uint8_t memberThreshold = 0; // T (real)
  uint8_t value[32] = {};
  uint8_t valueLen = 0;
};

// ---- Codificacion/decodificacion de mnemonic ----
inline bool decode_share(const String& mnemonic, Share& out) {
  // tokenizar
  std::vector<uint16_t> idx;
  {
    String s = mnemonic;
    s.trim();
    int start = 0;
    while (start < s.length()) {
      int sp = s.indexOf(' ', start);
      String word = sp < 0 ? s.substring(start) : s.substring(start, sp);
      word.trim();
      if (word.length()) {
        // lookup
        int found = -1;
        for (int i = 0; i < slip39::kWordCount; ++i)
          if (word.equals(slip39::kWords[i])) { found = i; break; }
        if (found < 0) return false;
        idx.push_back(static_cast<uint16_t>(found));
      }
      if (sp < 0) break;
      start = sp + 1;
    }
  }
  const size_t total = idx.size();
  if (total != 20 && total != 33) return false;
  const char* cs = "shamir";
  // ext depende del bit; lo determinamos tras leer el campo, pero el cs depende
  // de ext, asi que probamos ambos.
  std::vector<uint16_t> data(idx.begin(), idx.end());
  bool ok = rs1024_verify("shamir", data);
  if (!ok) ok = rs1024_verify("shamir_extendable", data);
  if (!ok) return false;

  out.id = (idx[0] << 5) | (idx[1] >> 5);
  out.ext = (idx[1] >> 4) & 1;
  out.e = idx[1] & 0xF;
  out.groupIndex = idx[2] >> 6;
  out.groupThreshold = ((idx[2] >> 2) & 0xF) + 1;
  out.groupCount = (((idx[2] & 3) << 2) | (idx[3] >> 8)) + 1;
  out.memberIndex = (idx[3] >> 4) & 0xF;
  out.memberThreshold = (idx[3] & 0xF) + 1;
  out.valueLen = (total == 20) ? 16 : 32;

  // Reconstruir el bitstream de ps (palabras 4..total-4) y extraer el valor
  // (los ultimos valueLen*8 bits).
  const size_t psWords = total - 4 - 3;  // 13 o 26
  uint8_t bits[260] = {};  // 26*10 = 260
  size_t bitPos = 0;
  for (size_t w = 0; w < psWords; ++w) {
    uint16_t v = idx[4 + w];
    for (int b = 9; b >= 0; --b) bits[bitPos++] = (v >> b) & 1;
  }
  const size_t psBits = psWords * 10;
  const size_t valueBits = out.valueLen * 8;
  const size_t padBits = psBits - valueBits;
  for (size_t k = 0; k < valueBits; ++k) {
    const size_t src = padBits + k;
    out.value[k / 8] |= (bits[src] ? (1u << (7 - (k % 8))) : 0);
  }
  return true;
}

inline String encode_share(const Share& s) {
  std::vector<uint16_t> words;
  words.push_back(s.id >> 5);
  words.push_back(((s.id & 0x1F) << 5) | (s.ext ? 0x10 : 0) | s.e);
  words.push_back((s.groupIndex << 6) | ((s.groupThreshold - 1) << 2) | ((s.groupCount - 1) >> 2));
  words.push_back((((s.groupCount - 1) & 3) << 8) | (s.memberIndex << 4) | (s.memberThreshold - 1));

  // ps: valor left-padded a multiplo de 10 bits.
  const size_t valueBits = s.valueLen * 8;
  const uint8_t pad = (10 - (valueBits % 10)) % 10;
  uint8_t bits[260] = {};
  size_t bitPos = 0;
  for (uint8_t p = 0; p < pad; ++p) bits[bitPos++] = 0;
  for (size_t k = 0; k < valueBits; ++k)
    bits[bitPos++] = (s.value[k / 8] >> (7 - (k % 8))) & 1;
  for (size_t w = 0; w < (pad + valueBits) / 10; ++w) {
    uint16_t v = 0;
    for (int b = 0; b < 10; ++b) v = (v << 1) | bits[w * 10 + b];
    words.push_back(v);
  }

  uint16_t chk[3];
  rs1024_checksum(s.ext ? "shamir_extendable" : "shamir", words, chk);
  words.push_back(chk[0]); words.push_back(chk[1]); words.push_back(chk[2]);

  String out;
  for (size_t i = 0; i < words.size(); ++i) {
    if (i) out += ' ';
    out += slip39::kWords[words[i]];
  }
  return out;
}

// ---- API de alto nivel ----
// Parte la entropia (16/32 bytes) en `count` shares con umbral `threshold`.
inline bool generate_mnemonics(uint8_t threshold, uint8_t count,
                               const uint8_t* secret, uint8_t secretLen,
                               const char* passphrase, String* outMnemonics) {
  if (threshold == 0 || threshold > count || count > kMaxShares) return false;
  if (secretLen != 16 && secretLen != 32) return false;

  uint16_t id = 0;
  esp_fill_random(reinterpret_cast<uint8_t*>(&id), 2);
  id &= 0x7FFF;  // 15 bits
  const bool ext = true;
  const uint8_t e = 0;

  uint8_t ems[32] = {};
  encrypt_ms(secret, secretLen, passphrase, e, id, ext, ems);

  uint8_t shares[16][32];
  split_secret(threshold, count, ems, secretLen, shares);

  for (uint8_t i = 0; i < count; ++i) {
    Share s;
    s.id = id; s.ext = ext; s.e = e;
    s.groupIndex = 0; s.groupThreshold = 1; s.groupCount = 1;
    s.memberIndex = i; s.memberThreshold = threshold;
    s.valueLen = secretLen;
    memcpy(s.value, shares[i], secretLen);
    outMnemonics[i] = encode_share(s);
    wipe(s.value, sizeof(s.value));
  }
  wipe(ems, sizeof(ems)); wipe(shares, sizeof(shares));
  return true;
}

// Combina `count` mnemonics para recuperar el master secret.
inline bool combine_mnemonics(uint8_t count, const String* mnemonics,
                              const char* passphrase, uint8_t* outSecret,
                              uint8_t* outSecretLen) {
  if (count == 0 || count > kMaxShares) return false;
  Share shares[16];
  for (uint8_t i = 0; i < count; ++i)
    if (!decode_share(mnemonics[i], shares[i])) return false;

  // Verificar consistencia: mismo id, ext, e, GT, G, longitud y umbral.
  for (uint8_t i = 1; i < count; ++i) {
    if (shares[i].id != shares[0].id || shares[i].ext != shares[0].ext ||
        shares[i].e != shares[0].e ||
        shares[i].groupThreshold != shares[0].groupThreshold ||
        shares[i].groupCount != shares[0].groupCount ||
        shares[i].memberThreshold != shares[0].memberThreshold ||
        shares[i].valueLen != shares[0].valueLen) return false;
    if (shares[i].groupIndex != 0) return false;
  }

  const uint8_t T = shares[0].memberThreshold;
  if (count < T) return false;

  uint8_t xs[16];
  const uint8_t* ys[16];
  for (uint8_t i = 0; i < count; ++i) {
    xs[i] = shares[i].memberIndex;
    ys[i] = shares[i].value;
  }

  uint8_t ems[32] = {};
  if (!recover_secret(T, xs, ys, count, shares[0].valueLen, ems)) return false;

  uint8_t ms[32] = {};
  decrypt_ms(ems, shares[0].valueLen, passphrase, shares[0].e, shares[0].id,
             shares[0].ext, ms);
  memcpy(outSecret, ms, shares[0].valueLen);
  *outSecretLen = shares[0].valueLen;
  wipe(ems, sizeof(ems)); wipe(ms, sizeof(ms));
  wipe(shares, sizeof(shares));
  return true;
}

inline bool self_test() {
  // 1) Shamir roundtrip 2-of-3, 16 bytes.
  {
    uint8_t secret[16];
    for (uint8_t i = 0; i < 16; ++i) secret[i] = i * 7 + 3;
    uint8_t shares[16][32];
    split_secret(2, 3, secret, 16, shares);
    const uint8_t* ys[2] = {shares[0], shares[2]};
    const uint8_t xs[2] = {0, 2};
    uint8_t rec[16];
    if (!recover_secret(2, xs, ys, 2, 16, rec) || memcmp(rec, secret, 16) != 0)
      return false;
    wipe(secret, sizeof(secret)); wipe(shares, sizeof(shares)); wipe(rec, sizeof(rec));
  }
  // 2) Vector oficial 1-of-1 (128 bits, passphrase "TREZOR").
  {
    const String mnem =
        "duckling enlarge academic academic agency result length solution fridge "
        "kidney coal piece deal husband erode duke ajar critical decision keyboard";
    uint8_t secret[32]; uint8_t secretLen = 0;
    if (!combine_mnemonics(1, &mnem, "TREZOR", secret, &secretLen)) return false;
    static const uint8_t expected[16] = {
        0xbb,0x54,0xaa,0xc4,0xb8,0x9d,0xc8,0x68,0xba,0x37,0xd9,0xcc,0x21,0xb2,0xce,0xce};
    if (secretLen != 16 || memcmp(secret, expected, 16) != 0) return false;
    wipe(secret, sizeof(secret));
  }
  // 3) Vector oficial 2-of-3 (128 bits, passphrase "TREZOR").
  {
    const String mn[2] = {
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder "
      "mustang wrist rescue view short owner flip making coding armed",
      "shadow pistol academic acid actress prayer class unknown daughter sweater "
      "depict flip twice unkind craft early superior advocate guest smoking"};
    uint8_t secret[32]; uint8_t secretLen = 0;
    if (!combine_mnemonics(2, mn, "TREZOR", secret, &secretLen)) return false;
    static const uint8_t expected[16] = {
        0xb4,0x3c,0xeb,0x7e,0x57,0xa0,0xea,0x87,0x66,0x22,0x16,0x24,0xd0,0x1b,0x08,0x64};
    if (secretLen != 16 || memcmp(secret, expected, 16) != 0) return false;
    wipe(secret, sizeof(secret));
  }
  return true;
}

}  // namespace slip39
