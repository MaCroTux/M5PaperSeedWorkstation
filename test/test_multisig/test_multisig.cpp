#include <unity.h>
#include "multisig.hpp"
#include "helpers.hpp"
#include <vector>

void setUp(void) { host::seedRandom(0x12345678u); }

void tearDown(void) {}

// Construye un script wsh(sortedmulti(...)) con keys ya ordenadas.
static std::vector<uint8_t> sortedmulti(uint8_t m, const uint8_t* const keys[], uint8_t n) {
  std::vector<uint8_t> s;
  s.push_back(0x50 + m);
  for (uint8_t i = 0; i < n; ++i) {
    s.push_back(0x21);
    s.insert(s.end(), keys[i], keys[i] + 33);
  }
  s.push_back(0x50 + n);
  s.push_back(0xae);  // OP_CHECKMULTISIG
  return s;
}

void test_parse_sorted_multi(void) {
  uint8_t k0[33] = {0x02, 0x10};
  uint8_t k1[33] = {0x02, 0x20};
  uint8_t k2[33] = {0x02, 0x30};
  const uint8_t* keys[3] = {k0, k1, k2};

  auto script = sortedmulti(2, keys, 3);
  multisig::MultisigScript ms;
  TEST_ASSERT_TRUE(multisig::parseSortedMulti(script.data(), script.size(), ms));
  TEST_ASSERT_TRUE(ms.valid);
  TEST_ASSERT_EQUAL_UINT8(2, ms.m);
  TEST_ASSERT_EQUAL_UINT8(3, ms.n);
  TEST_ASSERT_TRUE(testutil::eq(ms.keys[0], k0, 33));
  TEST_ASSERT_TRUE(testutil::eq(ms.keys[2], k2, 33));
}

void test_parse_sorted_multi_m_greater_n(void) {
  uint8_t k0[33] = {0x02, 0x10};
  uint8_t k1[33] = {0x02, 0x20};
  const uint8_t* keys[2] = {k0, k1};

  // m=3 > n=2 -> invalido.
  auto script = sortedmulti(3, keys, 2);
  multisig::MultisigScript ms;
  TEST_ASSERT_FALSE(multisig::parseSortedMulti(script.data(), script.size(), ms));
}

void test_parse_sorted_multi_unsorted(void) {
  uint8_t k0[33] = {0x02, 0x30};  // desordenada (mayor primero)
  uint8_t k1[33] = {0x02, 0x10};
  const uint8_t* keys[2] = {k0, k1};

  auto script = sortedmulti(2, keys, 2);
  multisig::MultisigScript ms;
  TEST_ASSERT_FALSE(multisig::parseSortedMulti(script.data(), script.size(), ms));
}

void test_parse_sorted_multi_truncated(void) {
  uint8_t k0[33] = {0x02, 0x10};
  const uint8_t* keys[1] = {k0};
  auto script = sortedmulti(1, keys, 1);
  script.pop_back();  // quitar OP_CHECKMULTISIG
  multisig::MultisigScript ms;
  TEST_ASSERT_FALSE(multisig::parseSortedMulti(script.data(), script.size(), ms));
}

void test_find_sig(void) {
  uint8_t pub[33] = {0x02, 0x55};
  std::vector<psbt::PartialSig> sigs;
  psbt::PartialSig ps;
  memcpy(ps.pub, pub, 33);
  ps.sigLen = 3;
  ps.sig[0] = 0xaa;
  ps.sig[1] = 0xbb;
  ps.sig[2] = 0xcc;
  sigs.push_back(ps);

  const uint8_t* out = nullptr;
  size_t outLen = 0;
  TEST_ASSERT_TRUE(multisig::findSig(sigs, pub, &out, &outLen));
  TEST_ASSERT_EQUAL_UINT(3, outLen);
  TEST_ASSERT_EQUAL_UINT8(0xbb, out[1]);

  uint8_t other[33] = {0x03, 0x77};
  TEST_ASSERT_FALSE(multisig::findSig(sigs, other, &out, &outLen));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_parse_sorted_multi);
  RUN_TEST(test_parse_sorted_multi_m_greater_n);
  RUN_TEST(test_parse_sorted_multi_unsorted);
  RUN_TEST(test_parse_sorted_multi_truncated);
  RUN_TEST(test_find_sig);
  return UNITY_END();
}
