#pragma once

#include <Arduino.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

#include "bip39_support.hpp"
#include "ripemd160_min.hpp"

namespace bitcoin_hd {

struct Node {
  uint8_t key[32];
  uint8_t chain[32];
};

inline void wipe(void* data, size_t size) {
  volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
  while (size--) *p++ = 0;
}

// RNG de hardware para blindar las multiplicaciones de curva (S-1).
inline int hw_rng(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

inline bool mnemonic_seed(const uint16_t* indices, size_t count, uint8_t seed[64],
                          const char* passphrase = "") {
  if (count != 12 && count != 24) return false;
  // Buffer fijo (no String) para poder limpiar la semilla mnemónica (S-2).
  char mnemonic[256] = {};
  size_t pos = 0;
  for (size_t i = 0; i < count; ++i) {
    if (indices[i] >= bip39::kWordCount) { wipe(mnemonic, sizeof(mnemonic)); return false; }
    const char* w = bip39::word_at(indices[i]);
    const size_t wlen = strlen(w);
    if (i) mnemonic[pos++] = ' ';
    memcpy(mnemonic + pos, w, wlen);
    pos += wlen;
  }
  mnemonic[pos] = '\0';

  char salt[80] = {};
  memcpy(salt, "mnemonic", 8);
  size_t slen = 8;
  if (passphrase && passphrase[0]) {
    const size_t plen = strlen(passphrase);
    memcpy(salt + slen, passphrase, plen);
    slen += plen;
  }
  salt[slen] = '\0';

  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t* sha512 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  const bool ok = sha512 && mbedtls_md_setup(&context, sha512, 1) == 0 &&
      mbedtls_pkcs5_pbkdf2_hmac(&context,
          reinterpret_cast<const uint8_t*>(mnemonic), pos,
          reinterpret_cast<const uint8_t*>(salt), slen, 2048, 64, seed) == 0;
  mbedtls_md_free(&context);
  wipe(mnemonic, sizeof(mnemonic));
  wipe(salt, sizeof(salt));
  return ok;
}

inline bool public_key(const Node& node, uint8_t out[33]) {
  mbedtls_ecp_group group; mbedtls_ecp_point point; mbedtls_mpi key;
  mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&key); size_t length = 0;
  const bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) == 0 &&
      mbedtls_mpi_read_binary(&key, node.key, 32) == 0 &&
      mbedtls_mpi_cmp_int(&key, 0) > 0 && mbedtls_mpi_cmp_mpi(&key, &group.N) < 0 &&
      mbedtls_ecp_mul(&group, &point, &key, &group.G, hw_rng, nullptr) == 0 &&
      mbedtls_ecp_point_write_binary(&group, &point, MBEDTLS_ECP_PF_COMPRESSED,
          &length, out, 33) == 0 && length == 33;
  mbedtls_mpi_free(&key); mbedtls_ecp_point_free(&point); mbedtls_ecp_group_free(&group);
  return ok;
}

inline bool master(const uint8_t seed[64], Node& out) {
  uint8_t digest[64] = {};
  const mbedtls_md_info_t* sha512 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (!sha512 || mbedtls_md_hmac(sha512,
          reinterpret_cast<const uint8_t*>("Bitcoin seed"), 12,
          seed, 64, digest) != 0) return false;
  memcpy(out.key, digest, 32); memcpy(out.chain, digest + 32, 32);
  wipe(digest, sizeof(digest));
  uint8_t pub[33] = {};
  const bool ok = public_key(out, pub);
  wipe(pub, sizeof(pub));
  return ok;
}

inline bool derive_hardened(const Node& parent, uint32_t child, Node& out) {
  const uint32_t index = child | 0x80000000UL;
  uint8_t data[37] = {}, digest[64] = {};
  memcpy(data + 1, parent.key, 32);
  data[33] = index >> 24; data[34] = index >> 16;
  data[35] = index >> 8; data[36] = index;
  const mbedtls_md_info_t* sha512 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (!sha512 || mbedtls_md_hmac(sha512, parent.chain, 32,
                                data, sizeof(data), digest) != 0) return false;
  bool ok = false;
  mbedtls_ecp_group group; mbedtls_mpi left, parentKey, result;
  mbedtls_ecp_group_init(&group); mbedtls_mpi_init(&left);
  mbedtls_mpi_init(&parentKey); mbedtls_mpi_init(&result);
  if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) == 0 &&
      mbedtls_mpi_read_binary(&left, digest, 32) == 0 &&
      mbedtls_mpi_cmp_mpi(&left, &group.N) < 0 &&
      mbedtls_mpi_read_binary(&parentKey, parent.key, 32) == 0 &&
      mbedtls_mpi_add_mpi(&result, &left, &parentKey) == 0 &&
      mbedtls_mpi_mod_mpi(&result, &result, &group.N) == 0 &&
      mbedtls_mpi_cmp_int(&result, 0) != 0 &&
      mbedtls_mpi_write_binary(&result, out.key, 32) == 0) {
    memcpy(out.chain, digest + 32, 32); ok = true;
  }
  mbedtls_mpi_free(&result); mbedtls_mpi_free(&parentKey); mbedtls_mpi_free(&left);
  mbedtls_ecp_group_free(&group); wipe(data, sizeof(data)); wipe(digest, sizeof(digest));
  return ok;
}

inline bool derive_normal(const Node& parent, uint32_t index, Node& out) {
  if (index >= 0x80000000UL) return false;
  uint8_t data[37] = {}, digest[64] = {};
  if (!public_key(parent, data)) return false;
  data[33] = index >> 24; data[34] = index >> 16;
  data[35] = index >> 8; data[36] = index;
  const mbedtls_md_info_t* sha512 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (!sha512 || mbedtls_md_hmac(sha512, parent.chain, 32,
                                data, sizeof(data), digest) != 0) return false;
  bool ok = false;
  mbedtls_ecp_group group; mbedtls_mpi left, parentKey, result;
  mbedtls_ecp_group_init(&group); mbedtls_mpi_init(&left);
  mbedtls_mpi_init(&parentKey); mbedtls_mpi_init(&result);
  if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) == 0 &&
      mbedtls_mpi_read_binary(&left, digest, 32) == 0 &&
      mbedtls_mpi_cmp_mpi(&left, &group.N) < 0 &&
      mbedtls_mpi_read_binary(&parentKey, parent.key, 32) == 0 &&
      mbedtls_mpi_add_mpi(&result, &left, &parentKey) == 0 &&
      mbedtls_mpi_mod_mpi(&result, &result, &group.N) == 0 &&
      mbedtls_mpi_cmp_int(&result, 0) != 0 &&
      mbedtls_mpi_write_binary(&result, out.key, 32) == 0) {
    memcpy(out.chain, digest + 32, 32); ok = true;
  }
  mbedtls_mpi_free(&result); mbedtls_mpi_free(&parentKey); mbedtls_mpi_free(&left);
  mbedtls_ecp_group_free(&group); wipe(data, sizeof(data)); wipe(digest, sizeof(digest));
  return ok;
}

inline bool account_node(const uint16_t* words, size_t count, uint32_t purpose,
                         Node& account, const char* passphrase = "") {
  uint8_t seed[64] = {}; Node root = {}, purposeNode = {}, coinNode = {};
  bool ok = mnemonic_seed(words, count, seed, passphrase) && master(seed, root);
  if (ok) ok = derive_hardened(root, purpose, purposeNode);
  if (ok) ok = derive_hardened(purposeNode, 0, coinNode);
  if (ok) ok = derive_hardened(coinNode, 0, account);
  wipe(seed, sizeof(seed)); wipe(&root, sizeof(root));
  wipe(&purposeNode, sizeof(purposeNode)); wipe(&coinNode, sizeof(coinNode));
  return ok;
}

inline void fingerprint(const Node& node, uint8_t out[4]) {
  uint8_t pub[33] = {}, sha[32] = {}, hash[20] = {};
  if (public_key(node, pub) && mbedtls_sha256_ret(pub, 33, sha, 0) == 0) {
    ripemd160_min::hash(sha, sizeof(sha), hash); memcpy(out, hash, 4);
  }
  wipe(pub, sizeof(pub)); wipe(sha, sizeof(sha)); wipe(hash, sizeof(hash));
}

inline String base58check(const uint8_t payload[78]) {
  uint8_t all[82] = {}, hash1[32] = {}, hash2[32] = {}, digits[116] = {};
  memcpy(all, payload, 78);
  if (mbedtls_sha256_ret(all, 78, hash1, 0) != 0 ||
      mbedtls_sha256_ret(hash1, 32, hash2, 0) != 0) return String();
  memcpy(all + 78, hash2, 4);
  size_t digitCount = 1;
  for (size_t i = 0; i < sizeof(all); ++i) {
    uint32_t carry = all[i];
    for (size_t j = 0; j < digitCount; ++j) {
      carry += static_cast<uint32_t>(digits[j]) << 8;
      digits[j] = carry % 58; carry /= 58;
    }
    while (carry) { digits[digitCount++] = carry % 58; carry /= 58; }
  }
  static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  String result; result.reserve(112);
  size_t zeroes = 0; while (zeroes < sizeof(all) && all[zeroes] == 0) ++zeroes;
  while (zeroes--) result += '1';
  while (digitCount && digits[digitCount - 1] == 0) --digitCount;
  while (digitCount) result += alphabet[digits[--digitCount]];
  wipe(all, sizeof(all)); wipe(hash1, sizeof(hash1)); wipe(hash2, sizeof(hash2));
  wipe(digits, sizeof(digits));
  return result;
}

inline bool account_key(const uint16_t* words, size_t count, uint32_t purpose,
                        uint32_t version, String& encoded, const char* passphrase = "") {
  uint8_t seed[64] = {}, parentFpr[4] = {}, pub[33] = {}, serialized[78] = {};
  Node nodes[4] = {};
  bool ok = mnemonic_seed(words, count, seed, passphrase) && master(seed, nodes[0]);
  if (ok) ok = derive_hardened(nodes[0], purpose, nodes[1]);
  if (ok) ok = derive_hardened(nodes[1], 0, nodes[2]);
  if (ok) { fingerprint(nodes[2], parentFpr); ok = derive_hardened(nodes[2], 0, nodes[3]); }
  if (ok) ok = public_key(nodes[3], pub);
  if (ok) {
    serialized[0] = version >> 24; serialized[1] = version >> 16;
    serialized[2] = version >> 8; serialized[3] = version;
    serialized[4] = 3; memcpy(serialized + 5, parentFpr, 4);
    serialized[9] = 0x80; serialized[10] = serialized[11] = serialized[12] = 0;
    memcpy(serialized + 13, nodes[3].chain, 32); memcpy(serialized + 45, pub, 33);
    encoded = base58check(serialized); ok = encoded.length() > 0;
  }
  wipe(seed, sizeof(seed)); wipe(nodes, sizeof(nodes)); wipe(parentFpr, sizeof(parentFpr));
  wipe(pub, sizeof(pub)); wipe(serialized, sizeof(serialized));
  return ok;
}

inline bool self_test_passphrase() {
  uint16_t words[12] = {};
  const uint16_t abandon = bip39::find_exact("abandon", bip39::Wordlist::English);
  const uint16_t about = bip39::find_exact("about", bip39::Wordlist::English);
  if (abandon == bip39::kInvalidWord || about == bip39::kInvalidWord) return false;
  for (uint8_t i = 0; i < 11; ++i) words[i] = abandon; words[11] = about;
  static const uint8_t expected[64] = {
    0xc5,0x52,0x57,0xc3,0x60,0xc0,0x7c,0x72,0x02,0x9a,0xeb,0xc1,0xb5,0x3c,0x05,0xed,
    0x03,0x62,0xad,0xa3,0x8e,0xad,0x3e,0x3e,0x9e,0xfa,0x37,0x08,0xe5,0x34,0x95,0x53,
    0x1f,0x09,0xa6,0x98,0x75,0x99,0xd1,0x82,0x64,0xc1,0xe1,0xc9,0x2f,0x2c,0xf1,0x41,
    0x63,0x0c,0x7a,0x3c,0x4a,0xb7,0xc8,0x1b,0x2f,0x00,0x16,0x98,0xe7,0x46,0x3b,0x04};
  uint8_t seed[64] = {};
  const bool ok = mnemonic_seed(words, 12, seed, "TREZOR") && !memcmp(seed, expected, 64);
  wipe(seed, sizeof(seed)); wipe(words, sizeof(words)); return ok;
}

inline bool account_key(const uint16_t* words, size_t count, bool nativeSegwit,
                        String& encoded) {
  return account_key(words, count, nativeSegwit ? 84 : 44,
                     nativeSegwit ? 0x04b24746UL : 0x0488b21eUL, encoded);
}

inline bool self_test() {
  uint16_t words[12];
  const uint16_t abandon = bip39::find_exact("abandon", bip39::Wordlist::English);
  const uint16_t about = bip39::find_exact("about", bip39::Wordlist::English);
  if (abandon == bip39::kInvalidWord || about == bip39::kInvalidWord) return false;
  for (uint8_t i = 0; i < 11; ++i) words[i] = abandon;
  words[11] = about;
  String zpub;
  const bool ok = account_key(words, 12, true, zpub) &&
      zpub == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
  zpub = ""; wipe(words, sizeof(words)); return ok;
}

}  // namespace bitcoin_hd
