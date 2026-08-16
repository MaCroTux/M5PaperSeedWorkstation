#include <unity.h>
#include "bip39_support.hpp"
#include "bip39_wordlist.h"
#include "bitcoin_hd.hpp"
#include "bip39_vectors.h"
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

static void buildMnemonic(const uint16_t* indices, uint8_t count, String& out) {
  out = "";
  for (uint8_t i = 0; i < count; ++i) {
    if (i) out += ' ';
    out += bip39::word_at(indices[i]);
  }
}

// Validacion completa de creacion/restauracion de semilla contra embit:
// entropia -> mnemonic (from_entropy), checksum, roundtrip to_entropy y
// mnemonic -> seed (PBKDF2).
void test_bip39_vectors(void) {
  for (size_t v = 0; v < kBip39VectorCount; ++v) {
    const Bip39Vector& vec = kBip39Vectors[v];
    const std::vector<uint8_t> entropy = testutil::hex(vec.entropyHex);
    const uint8_t wc = vec.wordCount;
    const uint8_t entropyBytes = wc == 12 ? 16 : 32;

    uint16_t indices[24] = {};
    TEST_ASSERT_TRUE(bip39::from_entropy(entropy.data(), entropyBytes, indices, wc));

    String mnemonic;
    buildMnemonic(indices, wc, mnemonic);
    TEST_ASSERT_TRUE(mnemonic.equals(vec.mnemonic));

    TEST_ASSERT_TRUE(bip39::checksum_valid(indices, wc));

    uint8_t back[32] = {};
    TEST_ASSERT_TRUE(bip39::to_entropy(indices, wc, back));
    TEST_ASSERT_TRUE(testutil::eq(back, entropy.data(), entropyBytes));

    uint8_t seed[64] = {};
    TEST_ASSERT_TRUE(bitcoin_hd::mnemonic_seed(indices, wc, seed, ""));
    const std::vector<uint8_t> expSeed = testutil::hex(vec.seedHex);
    TEST_ASSERT_TRUE(testutil::eq(seed, expSeed.data(), 64));
    bitcoin_hd::wipe(seed, 64);
    bitcoin_hd::wipe(back, 32);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_word_at);
  RUN_TEST(test_find_exact);
  RUN_TEST(test_find_matches);
  RUN_TEST(test_has_prefix);
  RUN_TEST(test_checksum_valid);
  RUN_TEST(test_from_entropy);
  RUN_TEST(test_self_test);
  RUN_TEST(test_bip39_vectors);
  return UNITY_END();
}
