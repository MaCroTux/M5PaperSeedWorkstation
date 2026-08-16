#include <unity.h>
#include "bip39_support.hpp"
#include "bip39_wordlist.h"
#include "helpers.hpp"

void setUp(void) {}

void tearDown(void) {}

static void make_abandon_about(uint16_t out[12]) {
  for (uint8_t i = 0; i < 11; ++i) out[i] = bip39::find_exact("abandon");
  out[11] = bip39::find_exact("about");
}

void test_word_at(void) {
  TEST_ASSERT_EQUAL_STRING("abandon", bip39::word_at(0));
  TEST_ASSERT_EQUAL_STRING("zoo", bip39::word_at(2047));
  TEST_ASSERT_EQUAL_STRING("---", bip39::word_at(2048));
}

void test_find_exact(void) {
  TEST_ASSERT_EQUAL_UINT16(0, bip39::find_exact("abandon"));
  TEST_ASSERT_EQUAL_UINT16(2047, bip39::find_exact("zoo"));
  TEST_ASSERT_EQUAL_UINT16(bip39::kInvalidWord, bip39::find_exact("notaword"));
  TEST_ASSERT_EQUAL_UINT16(bip39::kInvalidWord, bip39::find_exact(""));
}

void test_find_matches(void) {
  uint16_t matches[32] = {};
  const size_t total = bip39::find_matches("ab", matches, 32);
  TEST_ASSERT_EQUAL_UINT(10, total);  // abandon..abuse son exactamente 10
  TEST_ASSERT_EQUAL_UINT16(0, matches[0]);   // abandon
  TEST_ASSERT_EQUAL_UINT16(1, matches[1]);   // ability
  TEST_ASSERT_EQUAL_UINT16(2, matches[2]);   // able
  TEST_ASSERT_EQUAL_UINT16(3, matches[3]);   // about

  // Prefijo vacio -> 0 resultados.
  TEST_ASSERT_EQUAL_UINT16(0, bip39::find_matches("", matches, 32));
}

void test_has_prefix(void) {
  TEST_ASSERT_TRUE(bip39::has_prefix("ab"));
  TEST_ASSERT_TRUE(bip39::has_prefix("zoo"));
  TEST_ASSERT_FALSE(bip39::has_prefix("zzz"));
}

void test_checksum_valid(void) {
  uint16_t words[12];
  make_abandon_about(words);
  TEST_ASSERT_TRUE(bip39::checksum_valid(words, 12));

  // Contar con numero de palabras incorrecto.
  TEST_ASSERT_FALSE(bip39::checksum_valid(words, 13));
  TEST_ASSERT_FALSE(bip39::checksum_valid(words, 24));

  // Alterar la ultima palabra rompe el checksum.
  uint16_t bad[12];
  for (uint8_t i = 0; i < 12; ++i) bad[i] = words[i];
  bad[11] = bip39::find_exact("ability");
  TEST_ASSERT_FALSE(bip39::checksum_valid(bad, 12));

  // Indice fuera de rango.
  uint16_t oob[12];
  for (uint8_t i = 0; i < 12; ++i) oob[i] = words[i];
  oob[0] = 2048;
  TEST_ASSERT_FALSE(bip39::checksum_valid(oob, 12));
}

void test_from_entropy(void) {
  // Entropia toda cero (16 bytes) -> "abandon x11 + about".
  uint8_t entropy[16] = {};
  uint16_t indices[12] = {};
  TEST_ASSERT_TRUE(bip39::from_entropy(entropy, 16, indices, 12));
  for (uint8_t i = 0; i < 11; ++i)
    TEST_ASSERT_EQUAL_UINT16(0, indices[i]);
  TEST_ASSERT_EQUAL_UINT16(3, indices[11]);  // "about"

  // Tamaños inconsistentes.
  TEST_ASSERT_FALSE(bip39::from_entropy(entropy, 16, indices, 24));
  TEST_ASSERT_FALSE(bip39::from_entropy(entropy, 32, indices, 12));
}

void test_self_test(void) { TEST_ASSERT_TRUE(bip39::self_test()); }

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_word_at);
  RUN_TEST(test_find_exact);
  RUN_TEST(test_find_matches);
  RUN_TEST(test_has_prefix);
  RUN_TEST(test_checksum_valid);
  RUN_TEST(test_from_entropy);
  RUN_TEST(test_self_test);
  return UNITY_END();
}
