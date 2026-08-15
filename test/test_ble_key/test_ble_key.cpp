#include <unity.h>
#include "ble_key.hpp"
#include "helpers.hpp"

void setUp(void) {
  host_prefs::reset();
  host::seedRandom(0x12345678u);
}

void tearDown(void) {}

void test_hmac_sha256_rfc4231(void) {
  uint8_t key[20];
  memset(key, 0x0b, sizeof(key));
  const char* data = "Hi There";
  uint8_t out[32] = {};
  TEST_ASSERT_TRUE(ble_key::hmacSha256(key, 20, reinterpret_cast<const uint8_t*>(data),
                                       8, out));
  const auto expected = testutil::hex(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 32));
}

void test_keypair(void) {
  uint8_t priv[ble_key::kKeySize] = {}, pub[ble_key::kPubKeySize] = {};
  TEST_ASSERT_TRUE(ble_key::generateKeyPair(priv, pub));
  TEST_ASSERT_EQUAL_UINT8(0x04, pub[0]);  // sin comprimir

  uint8_t pub2[ble_key::kPubKeySize] = {};
  TEST_ASSERT_TRUE(ble_key::derivePublicKey(priv, pub2));
  TEST_ASSERT_TRUE(testutil::eq(pub, pub2, ble_key::kPubKeySize));
}

void test_ecdh_shared_kpair_symmetric(void) {
  uint8_t privA[32] = {}, pubA[65] = {};
  uint8_t privB[32] = {}, pubB[65] = {};
  TEST_ASSERT_TRUE(ble_key::generateKeyPair(privA, pubA));
  TEST_ASSERT_TRUE(ble_key::generateKeyPair(privB, pubB));

  uint8_t kpairAB[32] = {}, kpairBA[32] = {};
  TEST_ASSERT_TRUE(ble_key::deriveSharedKpair(privA, pubB, kpairAB));
  TEST_ASSERT_TRUE(ble_key::deriveSharedKpair(privB, pubA, kpairBA));
  TEST_ASSERT_TRUE(testutil::eq(kpairAB, kpairBA, 32));
}

void test_aes_gcm_roundtrip(void) {
  uint8_t key[32] = {};
  for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
  const uint8_t plain[] = {1, 2, 3, 4, 5};
  uint8_t enc[64] = {};
  size_t encLen = 0;
  TEST_ASSERT_TRUE(ble_key::aesGcmEncrypt(key, plain, sizeof(plain), enc, &encLen));
  TEST_ASSERT_EQUAL_UINT(12 + 5 + 16, encLen);

  uint8_t dec[8] = {};
  size_t decLen = 0;
  TEST_ASSERT_TRUE(ble_key::aesGcmDecrypt(key, enc, encLen, dec, &decLen));
  TEST_ASSERT_EQUAL_UINT(sizeof(plain), decLen);
  TEST_ASSERT_TRUE(testutil::eq(plain, dec, sizeof(plain)));
}

void test_ecies_roundtrip(void) {
  uint8_t sk[32] = {}, pk[65] = {};
  TEST_ASSERT_TRUE(ble_key::generateKeyPair(sk, pk));

  const uint8_t secret[] = "clave-maestra-del-vault";
  uint8_t blob[256] = {};
  size_t blobLen = 0;
  TEST_ASSERT_TRUE(ble_key::eciesEncrypt(pk, secret, sizeof(secret), blob, &blobLen));

  uint8_t rec[64] = {};
  size_t recLen = 0;
  TEST_ASSERT_TRUE(ble_key::eciesDecrypt(sk, blob, blobLen, rec, &recLen));
  TEST_ASSERT_EQUAL_UINT(sizeof(secret), recLen);
  TEST_ASSERT_TRUE(testutil::eq(secret, rec, sizeof(secret)));
}

void test_nvs_persistence(void) {
  uint8_t key[32] = {};
  for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(0x50 + i);

  TEST_ASSERT_FALSE(ble_key::hasStoredKey());
  TEST_ASSERT_TRUE(ble_key::saveStoredKey(key));
  TEST_ASSERT_TRUE(ble_key::hasStoredKey());

  uint8_t loaded[32] = {};
  TEST_ASSERT_TRUE(ble_key::loadStoredKey(loaded));
  TEST_ASSERT_TRUE(testutil::eq(key, loaded, 32));

  TEST_ASSERT_TRUE(ble_key::eraseStoredKey());
  TEST_ASSERT_FALSE(ble_key::hasStoredKey());
}

void test_hex_roundtrip(void) {
  uint8_t data[4] = {0x00, 0xab, 0xcd, 0xff};
  char hex[16] = {};
  ble_key::toHex(data, 4, hex);
  TEST_ASSERT_EQUAL_STRING("00abcdff", hex);

  uint8_t back[4] = {};
  TEST_ASSERT_EQUAL_UINT(4, ble_key::fromHex(hex, 8, back, 4));
  TEST_ASSERT_TRUE(testutil::eq(data, back, 4));

  // Longitud impar -> 0.
  TEST_ASSERT_EQUAL_UINT(0, ble_key::fromHex("abc", 3, back, 4));
}

void test_fingerprint_hex_format(void) {
  uint8_t pk[65] = {};
  pk[0] = 0x04;
  pk[1] = 0x01;
  pk[2] = 0x02;
  char out[10] = {};
  ble_key::fingerprintHex(pk, out);
  // Formato "XXXX XXXX" (8 hex + espacio).
  TEST_ASSERT_EQUAL_UINT8(' ', out[4]);
  TEST_ASSERT_EQUAL_UINT8('\0', out[9]);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_hmac_sha256_rfc4231);
  RUN_TEST(test_keypair);
  RUN_TEST(test_ecdh_shared_kpair_symmetric);
  RUN_TEST(test_aes_gcm_roundtrip);
  RUN_TEST(test_ecies_roundtrip);
  RUN_TEST(test_nvs_persistence);
  RUN_TEST(test_hex_roundtrip);
  RUN_TEST(test_fingerprint_hex_format);
  return UNITY_END();
}
