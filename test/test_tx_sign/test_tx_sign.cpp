#include <unity.h>
#include "tx_sign.hpp"
#include "helpers.hpp"

void setUp(void) { host::seedRandom(0x12345678u); }

void tearDown(void) {}

void test_hmac_sha256_rfc4231(void) {
  // RFC4231 Test Case 1.
  uint8_t key[20];
  memset(key, 0x0b, sizeof(key));
  const char* data = "Hi There";
  uint8_t out[32] = {};
  TEST_ASSERT_TRUE(tx_sign::hmacSha256(key, 20, reinterpret_cast<const uint8_t*>(data),
                                       8, out));
  const auto expected = testutil::hex(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 32));
}

void test_sha256d(void) {
  // double-SHA256 de cadena vacia.
  uint8_t out[32] = {};
  tx_sign::sha256d(nullptr, 0, out);
  const auto expected = testutil::hex(
      "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 32));
}

void test_der_roundtrip(void) {
  uint8_t r[32] = {};
  uint8_t s[32] = {};
  for (int i = 0; i < 32; ++i) {
    r[i] = static_cast<uint8_t>(i + 1);
    s[i] = static_cast<uint8_t>(0xff - i);
  }
  uint8_t der[73] = {};
  const size_t n = tx_sign::derEncode(r, s, der);
  TEST_ASSERT_GREATER_THAN(0, n);

  uint8_t rs[64] = {};
  TEST_ASSERT_TRUE(tx_sign::derDecode(der, n, rs));
  TEST_ASSERT_TRUE(testutil::eq(rs, r, 32));
  TEST_ASSERT_TRUE(testutil::eq(rs + 32, s, 32));
}

void test_script_purpose(void) {
  uint32_t purpose = 0;

  uint8_t p2wpkh[22] = {0x00, 0x14};
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2wpkh, 22, purpose));
  TEST_ASSERT_EQUAL_UINT(84, purpose);

  uint8_t p2pkh[25] = {0x76, 0xa9, 0x14};
  p2pkh[23] = 0x88;
  p2pkh[24] = 0xac;
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2pkh, 25, purpose));
  TEST_ASSERT_EQUAL_UINT(44, purpose);

  uint8_t p2sh[23] = {0xa9, 0x14};
  p2sh[22] = 0x87;
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2sh, 23, purpose));
  TEST_ASSERT_EQUAL_UINT(49, purpose);

  uint8_t p2tr[34] = {0x51, 0x20};
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2tr, 34, purpose));
  TEST_ASSERT_EQUAL_UINT(86, purpose);

  uint8_t unknown[2] = {0x01, 0x02};
  TEST_ASSERT_FALSE(tx_sign::scriptPurpose(unknown, 2, purpose));
}

void test_sign_deterministic(void) {
  static const uint8_t key[32] = {
      0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57,
      0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
      0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21};
  static const uint8_t msg[32] = {
      0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1, 0xD6,
      0x94, 0xF4, 0x1F, 0xC7, 0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
      0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF};

  uint8_t sig1[64] = {}, sig2[64] = {};
  TEST_ASSERT_TRUE(tx_sign::sign(key, msg, sig1));
  TEST_ASSERT_TRUE(tx_sign::sign(key, msg, sig2));
  TEST_ASSERT_TRUE(testutil::eq(sig1, sig2, 64));  // determinismo RFC6979
}

void test_self_test(void) { TEST_ASSERT_TRUE(tx_sign::self_test()); }

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_hmac_sha256_rfc4231);
  RUN_TEST(test_sha256d);
  RUN_TEST(test_der_roundtrip);
  RUN_TEST(test_script_purpose);
  RUN_TEST(test_sign_deterministic);
  RUN_TEST(test_self_test);
  return UNITY_END();
}
