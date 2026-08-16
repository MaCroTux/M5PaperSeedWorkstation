#include <unity.h>
#include "bitcoin_hd.hpp"
#include "bip39_wordlist.h"
#include "helpers.hpp"

void setUp(void) { host::seedRandom(0x12345678u); }

void tearDown(void) {}

static void make_abandon_about(uint16_t out[12]) {
  for (uint8_t i = 0; i < 11; ++i) out[i] = bip39::find_exact("abandon");
  out[11] = bip39::find_exact("about");
}

void test_mnemonic_seed(void) {
  uint16_t words[12];
  make_abandon_about(words);
  uint8_t seed[64] = {};
  TEST_ASSERT_TRUE(bitcoin_hd::mnemonic_seed(words, 12, seed));

  // BIP39: seed de "abandon ... about" sin passphrase.
  const auto expected = testutil::hex(
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
      "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
  TEST_ASSERT_TRUE(testutil::eq(seed, expected.data(), 64));

  // Numero de palabras invalido.
  TEST_ASSERT_FALSE(bitcoin_hd::mnemonic_seed(words, 11, seed));
}

void test_master_fingerprint(void) {
  uint16_t words[12];
  make_abandon_about(words);
  uint8_t seed[64] = {};
  bitcoin_hd::Node master = {};
  TEST_ASSERT_TRUE(bitcoin_hd::mnemonic_seed(words, 12, seed));
  TEST_ASSERT_TRUE(bitcoin_hd::master(seed, master));
  uint8_t fpr[4] = {};
  bitcoin_hd::fingerprint(master, fpr);
  const auto expected = testutil::hex("73c5da0a");
  TEST_ASSERT_TRUE(testutil::eq(fpr, expected.data(), 4));
}

void test_account_key_zpub(void) {
  uint16_t words[12];
  make_abandon_about(words);
  String zpub;
  TEST_ASSERT_TRUE(bitcoin_hd::account_key(words, 12, true, zpub));
  TEST_ASSERT_EQUAL_STRING(
      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1"
      "ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
      zpub.c_str());
}

void test_account_key_xpub(void) {
  uint16_t words[12];
  make_abandon_about(words);
  String xpub;
  // BIP44 m/44'/0'/0' con version xpub (0x0488b21e).
  TEST_ASSERT_TRUE(bitcoin_hd::account_key(words, 12, 44, 0x0488b21eUL, xpub));
  TEST_ASSERT_EQUAL_STRING(
      "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8"
      "Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
      xpub.c_str());
}

void test_self_test(void) {
  TEST_ASSERT_TRUE(bitcoin_hd::self_test());
  TEST_ASSERT_TRUE(bitcoin_hd::self_test_passphrase());
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_mnemonic_seed);
  RUN_TEST(test_master_fingerprint);
  RUN_TEST(test_account_key_zpub);
  RUN_TEST(test_account_key_xpub);
  RUN_TEST(test_self_test);
  return UNITY_END();
}
