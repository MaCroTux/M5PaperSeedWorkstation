#pragma once
#include <Arduino.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include "bip39_support.hpp"
#include "ripemd160_min.hpp"

namespace bitcoin_fingerprint {
inline bool calculate(const uint16_t* indices, size_t count, uint8_t out[4],
                      const char* passphrase = "") {
  if (count != 12 && count != 24) return false;
  String mnemonic;
  mnemonic.reserve(count * 9);
  for (size_t i = 0; i < count; ++i) {
    if (indices[i] >= bip39::kWordCount) return false;
    if (i) mnemonic += ' ';
    mnemonic += bip39::word_at(indices[i]);
  }
  uint8_t seed[64] = {}, master[64] = {}, pub[33] = {}, sha[32] = {};
  bool ok = false;
  mbedtls_md_context_t md;
  mbedtls_md_init(&md);
  const mbedtls_md_info_t* sha512 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  String salt = "mnemonic"; salt += passphrase ? passphrase : "";
  if (!sha512 || mbedtls_md_setup(&md, sha512, 1) != 0) goto cleanup;
  if (mbedtls_pkcs5_pbkdf2_hmac(&md,
          reinterpret_cast<const unsigned char*>(mnemonic.c_str()), mnemonic.length(),
          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(), 2048,
          sizeof(seed), seed) != 0) goto cleanup;
  if (mbedtls_md_hmac(sha512,
          reinterpret_cast<const unsigned char*>("Bitcoin seed"), 12,
          seed, sizeof(seed), master) != 0) goto cleanup;
  {
    mbedtls_ecp_group group; mbedtls_ecp_point point; mbedtls_mpi key;
    mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&key); size_t pub_len = 0;
    if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) == 0 &&
        mbedtls_mpi_read_binary(&key, master, 32) == 0 &&
        mbedtls_mpi_cmp_int(&key, 0) > 0 && mbedtls_mpi_cmp_mpi(&key, &group.N) < 0 &&
        mbedtls_ecp_mul(&group, &point, &key, &group.G, nullptr, nullptr) == 0 &&
        mbedtls_ecp_point_write_binary(&group, &point, MBEDTLS_ECP_PF_COMPRESSED,
            &pub_len, pub, sizeof(pub)) == 0 && pub_len == sizeof(pub) &&
        mbedtls_sha256_ret(pub, sizeof(pub), sha, 0) == 0) {
      uint8_t hash160[20] = {};
      ripemd160_min::hash(sha, sizeof(sha), hash160);
      memcpy(out, hash160, 4); ok = true;
      memset(hash160, 0, sizeof(hash160));
    }
    mbedtls_mpi_free(&key); mbedtls_ecp_point_free(&point);
    mbedtls_ecp_group_free(&group);
  }
cleanup:
  mbedtls_md_free(&md); mnemonic = ""; salt = "";
  memset(seed, 0, sizeof(seed)); memset(master, 0, sizeof(master));
  memset(pub, 0, sizeof(pub)); memset(sha, 0, sizeof(sha));
  return ok;
}

inline bool self_test() {
  uint16_t v[12];
  const uint16_t a = bip39::find_exact("abandon"), b = bip39::find_exact("about");
  if (a == bip39::kInvalidWord || b == bip39::kInvalidWord) return false;
  for (size_t i = 0; i < 11; ++i) v[i] = a; v[11] = b;
  uint8_t f[4] = {};
  return calculate(v, 12, f) && f[0] == 0x73 && f[1] == 0xc5 &&
         f[2] == 0xda && f[3] == 0x0a;
}
}  // namespace bitcoin_fingerprint
