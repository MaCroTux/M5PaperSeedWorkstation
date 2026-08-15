#include <unity.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include "bip39_support.hpp"
#include "encrypted_seed_store.hpp"
#include "helpers.hpp"

void setUp(void) {
  host_sd::reset();
  host::seedRandom(0x12345678u);
}

void tearDown(void) {}

static void make_words(uint16_t out[12]) {
  for (uint8_t i = 0; i < 11; ++i) out[i] = bip39::find_exact("abandon");
  out[11] = bip39::find_exact("about");
}

void test_pbkdf2_matches_mbedtls(void) {
  uint8_t salt[16] = {};
  for (int i = 0; i < 16; ++i) salt[i] = static_cast<uint8_t>(i * 7 + 1);

  uint8_t manual[32] = {}, reference[32] = {};
  TEST_ASSERT_TRUE(encrypted_seed_store::pbkdf2_sha256("secret", salt, 1000, manual));

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  TEST_ASSERT_NOT_NULL(info);
  TEST_ASSERT_EQUAL_INT(0, mbedtls_md_setup(&ctx, info, 1));
  TEST_ASSERT_EQUAL_INT(0, mbedtls_pkcs5_pbkdf2_hmac(
      &ctx, reinterpret_cast<const unsigned char*>("secret"), 6,
      salt, 16, 1000, 32, reference));
  mbedtls_md_free(&ctx);

  TEST_ASSERT_TRUE(testutil::eq(manual, reference, 32));
}

void test_derive_iteration_bounds(void) {
  uint8_t salt[16] = {};
  uint8_t key[32] = {};
  TEST_ASSERT_FALSE(encrypted_seed_store::derive("x", salt, 99999, key));
  TEST_ASSERT_FALSE(encrypted_seed_store::derive("", salt, 100000, key));
  TEST_ASSERT_TRUE(encrypted_seed_store::derive("x", salt, 100000, key));
}

void test_save_load_roundtrip(void) {
  uint16_t words[12];
  make_words(words);

  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    encrypted_seed_store::save("/seed.vlt", "pass123", words, 12));

  uint16_t loaded[12] = {};
  uint8_t count = 0;
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    encrypted_seed_store::load("/seed.vlt", "pass123", loaded, count));
  TEST_ASSERT_EQUAL_UINT8(12, count);
  TEST_ASSERT_TRUE(testutil::eq(reinterpret_cast<uint8_t*>(words),
                                reinterpret_cast<uint8_t*>(loaded), 24));
}

void test_save_exists(void) {
  uint16_t words[12];
  make_words(words);
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    encrypted_seed_store::save("/seed.vlt", "pass123", words, 12));
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::exists,
                    encrypted_seed_store::save("/seed.vlt", "pass123", words, 12));
}

void test_load_wrong_password(void) {
  uint16_t words[12];
  make_words(words);
  encrypted_seed_store::save("/seed.vlt", "pass123", words, 12);

  uint16_t loaded[12] = {};
  uint8_t count = 0;
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::wrong_password_or_tampered,
                    encrypted_seed_store::load("/seed.vlt", "nope", loaded, count));
}

void test_load_tampered(void) {
  uint16_t words[12];
  make_words(words);
  encrypted_seed_store::save("/seed.vlt", "pass123", words, 12);

  // Corrompe un byte del ciphertext (tras la cabecera de 40 bytes).
  auto& f = host_sd::files()[std::string("/seed.vlt")];
  f[40 + 5] ^= 0xff;

  uint16_t loaded[12] = {};
  uint8_t count = 0;
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::wrong_password_or_tampered,
                    encrypted_seed_store::load("/seed.vlt", "pass123", loaded, count));
}

void test_save_no_sd(void) {
  host_sd::setPresent(false);
  uint16_t words[12];
  make_words(words);
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::no_sd,
                    encrypted_seed_store::save("/seed.vlt", "pass123", words, 12));
}

void test_self_test(void) { TEST_ASSERT_TRUE(encrypted_seed_store::self_test()); }

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_pbkdf2_matches_mbedtls);
  RUN_TEST(test_derive_iteration_bounds);
  RUN_TEST(test_save_load_roundtrip);
  RUN_TEST(test_save_exists);
  RUN_TEST(test_load_wrong_password);
  RUN_TEST(test_load_tampered);
  RUN_TEST(test_save_no_sd);
  RUN_TEST(test_self_test);
  return UNITY_END();
}
