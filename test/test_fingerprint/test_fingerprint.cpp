#include <unity.h>
#include "bitcoin_fingerprint.hpp"
#include "bip39_wordlist.h"
#include "helpers.hpp"

void setUp(void) { host::seedRandom(0x12345678u); }

void tearDown(void) {}

void test_calculate(void) {
  uint16_t words[12];
  const uint16_t abandon = bip39::find_exact("abandon");
  const uint16_t about = bip39::find_exact("about");
  for (uint8_t i = 0; i < 11; ++i) words[i] = abandon;
  words[11] = about;

  uint8_t fpr[4] = {};
  TEST_ASSERT_TRUE(bitcoin_fingerprint::calculate(words, 12, fpr));
  const auto expected = testutil::hex("73c5da0a");
  TEST_ASSERT_TRUE(testutil::eq(fpr, expected.data(), 4));
}

void test_calculate_passphrase_changes(void) {
  uint16_t words[12];
  const uint16_t abandon = bip39::find_exact("abandon");
  const uint16_t about = bip39::find_exact("about");
  for (uint8_t i = 0; i < 11; ++i) words[i] = abandon;
  words[11] = about;

  uint8_t fprNoPass[4] = {}, fprPass[4] = {};
  bitcoin_fingerprint::calculate(words, 12, fprNoPass, "");
  bitcoin_fingerprint::calculate(words, 12, fprPass, "TREZOR");
  TEST_ASSERT_FALSE(testutil::eq(fprNoPass, fprPass, 4));
}

void test_self_test(void) { TEST_ASSERT_TRUE(bitcoin_fingerprint::self_test()); }

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_calculate);
  RUN_TEST(test_calculate_passphrase_changes);
  RUN_TEST(test_self_test);
  return UNITY_END();
}
