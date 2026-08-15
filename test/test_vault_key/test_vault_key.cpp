#include <unity.h>
#include "vault_key.hpp"
#include "helpers.hpp"

void setUp(void) {
  host_sd::reset();
  host_prefs::reset();
  host::seedRandom(0x12345678u);
}

void tearDown(void) {}

void test_build_path(void) {
  uint8_t vaultId[4] = {0x01, 0x02, 0x03, 0x04};
  char path[32] = {};
  vault_2fa::buildPath(vaultId, path, sizeof(path));
  TEST_ASSERT_EQUAL_STRING("/K2F-01020304.k2f", path);
}

void test_save_load_encrypted_sk(void) {
  uint8_t sk[32] = {};
  for (int i = 0; i < 32; ++i) sk[i] = static_cast<uint8_t>(i + 1);

  TEST_ASSERT_FALSE(vault_2fa::hasEncryptedSk());
  TEST_ASSERT_TRUE(vault_2fa::saveEncryptedSk(sk, "123456"));
  TEST_ASSERT_TRUE(vault_2fa::hasEncryptedSk());

  uint8_t loaded[32] = {};
  TEST_ASSERT_TRUE(vault_2fa::loadDecryptedSk("123456", loaded));
  TEST_ASSERT_TRUE(testutil::eq(sk, loaded, 32));
}

void test_load_sk_wrong_pin(void) {
  uint8_t sk[32] = {};
  vault_2fa::saveEncryptedSk(sk, "123456");

  uint8_t loaded[32] = {};
  TEST_ASSERT_FALSE(vault_2fa::loadDecryptedSk("000000", loaded));
}

void test_enable_read_blob_ecies(void) {
  // Genera un par de llaves del Core2.
  uint8_t sk[ble_key::kKeySize] = {}, pk[ble_key::kPubKeySize] = {};
  TEST_ASSERT_TRUE(ble_key::generateKeyPair(sk, pk));

  uint8_t master[32] = {};
  for (int i = 0; i < 32; ++i) master[i] = static_cast<uint8_t>(0xa0 + i);
  uint8_t vaultId[4] = {0xde, 0xad, 0xbe, 0xef};

  TEST_ASSERT_EQUAL(encrypted_seed_store::Result::ok,
                    vault_2fa::enable("/v.k2f", master, vaultId, "Label", pk));

  uint8_t blob[vault_2fa::kBlobSize] = {};
  TEST_ASSERT_TRUE(vault_2fa::readBlob("/v.k2f", blob));

  // Descifra el blob con la privada sk (como haria el Core2).
  uint8_t recovered[32] = {};
  size_t recoveredLen = 0;
  TEST_ASSERT_TRUE(ble_key::eciesDecrypt(sk, blob, vault_2fa::kBlobSize,
                                         recovered, &recoveredLen));
  TEST_ASSERT_EQUAL_UINT(32, recoveredLen);
  TEST_ASSERT_TRUE(testutil::eq(master, recovered, 32));

  // Metadatos.
  uint8_t vid[4] = {};
  char label[17] = {};
  TEST_ASSERT_TRUE(vault_2fa::readMeta("/v.k2f", vid, label));
  TEST_ASSERT_TRUE(testutil::eq(vaultId, vid, 4));
  TEST_ASSERT_EQUAL_STRING("Label", label);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_build_path);
  RUN_TEST(test_save_load_encrypted_sk);
  RUN_TEST(test_load_sk_wrong_pin);
  RUN_TEST(test_enable_read_blob_ecies);
  return UNITY_END();
}
