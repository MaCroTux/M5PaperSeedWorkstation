#pragma once
#include <Arduino.h>
#include <mbedtls/md.h>
#include "bip39_support.hpp"
#include "bitcoin_hd.hpp"

// BIP85 — Deterministic Entropy From BIP32 Keychains (BIP-0085).
//
// Deriva entropia determinista (o mnemonics hijas) desde la raiz BIP32 de la
// semilla activa: m/83696968'/{app}'/.../{index}', y transforma la clave
// derivada con HMAC-SHA512(key="bip-entropy-from-k", msg=k).
//
// Aplicacion BIP39 (39'): m/83696968'/39'/{lang}'/{words}'/{index}'
//   lang: 0 = ingles, 3 = espanol.  words: 12 o 24.

namespace bip85 {

constexpr uint32_t kPurpose = 83696968UL;

inline bool hmac_sha512(const uint8_t* key, size_t keyLen, const uint8_t* data,
                        size_t dataLen, uint8_t out[64]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  return info && mbedtls_md_hmac(info, key, keyLen, data, dataLen, out) == 0;
}

// Deriva m/83696968'/extra[0]'/.../extra[n-1]' y devuelve los 64 bytes de
// HMAC-SHA512("bip-entropy-from-k", k).
inline bool derive(const bitcoin_hd::Node& root, const uint32_t* extra,
                   size_t extraLen, uint8_t out64[64]) {
  bitcoin_hd::Node n = root, t = {};
  if (!bitcoin_hd::derive_hardened(n, kPurpose, t)) return false;
  n = t;
  for (size_t i = 0; i < extraLen; ++i) {
    if (!bitcoin_hd::derive_hardened(n, extra[i], t)) return false;
    n = t;
  }
  static const char tag[] = "bip-entropy-from-k";
  const bool ok = hmac_sha512(reinterpret_cast<const uint8_t*>(tag), 18,
                              n.key, 32, out64);
  bitcoin_hd::wipe(&n, sizeof(n)); bitcoin_hd::wipe(&t, sizeof(t));
  return ok;
}

// Aplicacion BIP39 (39'). Devuelve los indices BIP39 (wordCount palabras).
inline bool derive_words(const bitcoin_hd::Node& root, uint8_t langCode,
                         uint8_t wordCount, uint32_t index, uint16_t* outWords) {
  if (wordCount != 12 && wordCount != 24) return false;
  uint32_t extra[4] = {39, langCode, wordCount, index};
  uint8_t e64[64] = {};
  if (!derive(root, extra, 4, e64)) return false;
  const size_t bytes = wordCount == 12 ? 16 : 32;
  const bool ok = bip39::from_entropy(e64, bytes, outWords, wordCount);
  bitcoin_hd::wipe(e64, sizeof(e64));
  return ok;
}

inline bool derive_words(const uint16_t* mnemonic, size_t count, uint8_t langCode,
                         uint8_t wordCount, uint32_t index, uint16_t* outWords,
                         const char* passphrase = "") {
  uint8_t seed[64] = {};
  bitcoin_hd::Node root = {};
  bool ok = bitcoin_hd::mnemonic_seed(mnemonic, count, seed, passphrase) &&
            bitcoin_hd::master(seed, root);
  bitcoin_hd::wipe(seed, sizeof(seed));
  if (ok) ok = derive_words(root, langCode, wordCount, index, outWords);
  bitcoin_hd::wipe(&root, sizeof(root));
  return ok;
}

inline bool self_test() {
  // Root key del vector de test BIP85 (xprv9s21ZrQH143K2LBWUUQRFXhucrQqBp...).
  bitcoin_hd::Node root = {};
  static const uint8_t chain[32] = {
      0x1b,0x67,0x96,0x9d,0x1e,0xc6,0x9b,0xdf,0xee,0xae,0x43,0x21,0x3d,0xa8,
      0x46,0x0b,0xa3,0x4b,0x92,0xd0,0x78,0x8c,0x8f,0x7b,0xfc,0xfa,0x44,0x90,
      0x6e,0x8a,0x58,0x9c};
  static const uint8_t key[32] = {
      0x3f,0x15,0xe5,0xd8,0x52,0xdc,0x2e,0x9b,0xa5,0xe9,0xfe,0x18,0x9a,0x8d,
      0xd2,0xe1,0x54,0x7b,0xad,0xef,0x5b,0x56,0x3b,0xbe,0x65,0x79,0xfc,0x68,
      0x07,0xd8,0x0e,0xd9};
  memcpy(root.key, key, 32); memcpy(root.chain, chain, 32);

  uint16_t words[12] = {};
  if (!derive_words(root, 0, 12, 0, words)) return false;
  static const char* expected[] = {"girl","mad","pet","galaxy","egg","matter",
                                   "matrix","prison","refuse","sense","ordinary","nose"};
  for (uint8_t i = 0; i < 12; ++i) {
    if (strcmp(bip39::word_at(words[i], bip39::Wordlist::English), expected[i]) != 0) {
      bitcoin_hd::wipe(words, sizeof(words)); return false;
    }
  }
  bitcoin_hd::wipe(words, sizeof(words));
  bitcoin_hd::wipe(&root, sizeof(root));
  return true;
}

}  // namespace bip85
