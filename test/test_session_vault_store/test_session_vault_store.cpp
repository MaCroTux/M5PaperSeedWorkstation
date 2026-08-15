#include <unity.h>
#include "bip39_support.hpp"
#include "session_vault_store.hpp"
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

void test_create_unlock_roundtrip(void) {
  uint8_t master[32] = {}, vaultId[4] = {};
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    session_vault_store::create("/vault.svm", "MiVault", "masterpass",
                                                master, vaultId));

  uint8_t master2[32] = {}, vaultId2[4] = {};
  char label[17] = {};
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    session_vault_store::unlock("/vault.svm", "masterpass",
                                                master2, vaultId2, label));
  TEST_ASSERT_TRUE(testutil::eq(master, master2, 32));
  TEST_ASSERT_TRUE(testutil::eq(vaultId, vaultId2, 4));
  TEST_ASSERT_EQUAL_STRING("MiVault", label);
}

void test_create_exists(void) {
  uint8_t master[32] = {}, vaultId[4] = {};
  session_vault_store::create("/vault.svm", "MiVault", "masterpass", master, vaultId);
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::exists,
                    session_vault_store::create("/vault.svm", "MiVault", "masterpass",
                                                master, vaultId));
}

void test_unlock_wrong_password(void) {
  uint8_t master[32] = {}, vaultId[4] = {};
  session_vault_store::create("/vault.svm", "MiVault", "masterpass", master, vaultId);

  uint8_t master2[32] = {}, vaultId2[4] = {};
  char label[17] = {};
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::wrong_password_or_tampered,
                    session_vault_store::unlock("/vault.svm", "wrong", master2, vaultId2,
                                                label));
}

void test_save_load_seed_roundtrip(void) {
  uint8_t master[32] = {}, vaultId[4] = {};
  session_vault_store::create("/vault.svm", "MiVault", "masterpass", master, vaultId);

  uint16_t words[12];
  make_words(words);
  uint8_t fpr[4] = {0x73, 0xc5, 0xda, 0x0a};

  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    session_vault_store::save_seed("/seed.svs", master, vaultId,
                                                   "Seed1", fpr, words, 12));

  uint16_t loaded[12] = {};
  uint8_t count = 0, fpr2[4] = {};
  char label[17] = {};
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    session_vault_store::load_seed("/seed.svs", master, vaultId,
                                                   loaded, count, fpr2, label));
  TEST_ASSERT_EQUAL_UINT8(12, count);
  TEST_ASSERT_TRUE(testutil::eq(fpr, fpr2, 4));
  TEST_ASSERT_EQUAL_STRING("Seed1", label);
  TEST_ASSERT_TRUE(testutil::eq(reinterpret_cast<uint8_t*>(words),
                                reinterpret_cast<uint8_t*>(loaded), 24));
}

void test_load_seed_wrong_master(void) {
  uint8_t master[32] = {}, vaultId[4] = {};
  session_vault_store::create("/vault.svm", "MiVault", "masterpass", master, vaultId);

  uint16_t words[12];
  make_words(words);
  uint8_t fpr[4] = {0x73, 0xc5, 0xda, 0x0a};
  session_vault_store::save_seed("/seed.svs", master, vaultId, "Seed1", fpr, words, 12);

  uint8_t wrongMaster[32] = {};
  wrongMaster[0] = 0xff;
  uint16_t loaded[12] = {};
  uint8_t count = 0, fpr2[4] = {};
  char label[17] = {};
  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::wrong_password_or_tampered,
                    session_vault_store::load_seed("/seed.svs", wrongMaster, vaultId,
                                                   loaded, count, fpr2, label));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_create_unlock_roundtrip);
  RUN_TEST(test_create_exists);
  RUN_TEST(test_unlock_wrong_password);
  RUN_TEST(test_save_load_seed_roundtrip);
  RUN_TEST(test_load_seed_wrong_master);
  return UNITY_END();
}
