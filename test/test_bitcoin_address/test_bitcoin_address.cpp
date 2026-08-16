#include <unity.h>
#include "bitcoin_address.hpp"
#include "bip39_wordlist.h"
#include "helpers.hpp"

void setUp(void) { host::seedRandom(0x12345678u); }

void tearDown(void) {}

static void make_abandon_about(uint16_t out[12]) {
  for (uint8_t i = 0; i < 11; ++i) out[i] = bip39::find_exact("abandon");
  out[11] = bip39::find_exact("about");
}

void test_derive_p2wpkh(void) {
  uint16_t words[12];
  make_abandon_about(words);
  String addr;
  TEST_ASSERT_TRUE(bitcoin_address::derive(words, 12, 84, 0, 0, addr));
  TEST_ASSERT_EQUAL_STRING("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                           addr.c_str());

  // Rama de cambio m/84'/0'/0'/1/0.
  TEST_ASSERT_TRUE(bitcoin_address::derive(words, 12, 84, 1, 0, addr));
  TEST_ASSERT_EQUAL_STRING("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
                           addr.c_str());
}

void test_derive_p2pkh(void) {
  uint16_t words[12];
  make_abandon_about(words);
  String addr;
  TEST_ASSERT_TRUE(bitcoin_address::derive(words, 12, 44, 0, 0, addr));
  TEST_ASSERT_EQUAL_STRING("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", addr.c_str());
}

void test_derive_p2sh(void) {
  uint16_t words[12];
  make_abandon_about(words);
  String addr;
  TEST_ASSERT_TRUE(bitcoin_address::derive(words, 12, 49, 0, 0, addr));
  TEST_ASSERT_EQUAL_STRING("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", addr.c_str());
}

void test_derive_invalid_params(void) {
  uint16_t words[12];
  make_abandon_about(words);
  String addr;
  TEST_ASSERT_FALSE(bitcoin_address::derive(words, 12, 84, 2, 0, addr));  // change>1
  TEST_ASSERT_FALSE(bitcoin_address::derive(words, 12, 0, 0, 0, addr));   // purpose desconocido
}

void test_segwit_address(void) {
  // bech32 de un program de 20 bytes todo cero (version 0).
  uint8_t program[20] = {};
  String a = bitcoin_address::segwit_address(0, program, 20);
  TEST_ASSERT_EQUAL_STRING("bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs", a.c_str());

  // Version 2 no soportada -> vacio.
  TEST_ASSERT_EQUAL_STRING("", bitcoin_address::segwit_address(2, program, 20).c_str());
  // Longitud invalida -> vacio.
  TEST_ASSERT_EQUAL_STRING("", bitcoin_address::segwit_address(0, program, 16).c_str());
}

void test_base58_address(void) {
  // hash160 todo cero con prefijo 0x00 -> direccion P2PKH conocida.
  uint8_t hash[20] = {};
  String a = bitcoin_address::base58_address(0, hash);
  TEST_ASSERT_EQUAL_STRING("1111111111111111111114oLvT2", a.c_str());
}

void test_hash160(void) {
  // HASH160 de una cadena vacia.
  uint8_t out[20] = {};
  bitcoin_address::hash160(nullptr, 0, out);
  const auto expected = testutil::hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 20));
}

void test_self_test(void) {
  TEST_ASSERT_TRUE(bitcoin_address::self_test_bip84());
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_derive_p2wpkh);
  RUN_TEST(test_derive_p2pkh);
  RUN_TEST(test_derive_p2sh);
  RUN_TEST(test_derive_invalid_params);
  RUN_TEST(test_segwit_address);
  RUN_TEST(test_base58_address);
  RUN_TEST(test_hash160);
  RUN_TEST(test_self_test);
  return UNITY_END();
}
