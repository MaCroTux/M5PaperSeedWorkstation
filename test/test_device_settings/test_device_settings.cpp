#include <unity.h>
#include "device_settings.hpp"
#include "helpers.hpp"

void setUp(void) { host_sd::reset(); }

void tearDown(void) {}

void test_defaults(void) {
  auto s = device_settings::defaults();
  TEST_ASSERT_EQUAL_UINT8(0, s.language);
  TEST_ASSERT_EQUAL_UINT8(2, s.defaultProfile);
  TEST_ASSERT_EQUAL_UINT32(device_settings::kTimeout3m, s.lockTimeoutMs);
  TEST_ASSERT_EQUAL_UINT32(0, s.seedCleanTimeoutMs);
  TEST_ASSERT_EQUAL_UINT8(7, s.screenCleanEvery);
  TEST_ASSERT_TRUE(device_settings::valid(s));
}

void test_valid_rejects_bad(void) {
  auto s = device_settings::defaults();
  s.language = 2;
  TEST_ASSERT_FALSE(device_settings::valid(s));

  s = device_settings::defaults();
  s.lockTimeoutMs = 12345;  // no esta en las opciones
  TEST_ASSERT_FALSE(device_settings::valid(s));

  s = device_settings::defaults();
  s.defaultProfile = 3;
  TEST_ASSERT_FALSE(device_settings::valid(s));
}

void test_save_load_roundtrip(void) {
  auto s = device_settings::defaults();
  s.language = 1;              // espanol
  s.lockTimeoutMs = device_settings::kTimeout10m;
  s.seedCleanTimeoutMs = device_settings::kClean30m;
  s.screenCleanEvery = 10;
  TEST_ASSERT_TRUE(device_settings::save(s));

  auto l = device_settings::load();
  TEST_ASSERT_EQUAL_UINT8(1, l.language);
  TEST_ASSERT_EQUAL_UINT32(device_settings::kTimeout10m, l.lockTimeoutMs);
  TEST_ASSERT_EQUAL_UINT32(device_settings::kClean30m, l.seedCleanTimeoutMs);
  TEST_ASSERT_EQUAL_UINT8(10, l.screenCleanEvery);
}

void test_load_missing_file_returns_defaults(void) {
  auto l = device_settings::load();
  auto d = device_settings::defaults();
  TEST_ASSERT_EQUAL_UINT8(d.language, l.language);
  TEST_ASSERT_EQUAL_UINT32(d.lockTimeoutMs, l.lockTimeoutMs);
}

void test_load_legacy_v2(void) {
  // Formato antiguo v2: 15 bytes.
  File f = SD.open(device_settings::kPath, FILE_WRITE);
  TEST_ASSERT_TRUE(static_cast<bool>(f));
  uint8_t buf[15] = {};
  memcpy(buf, "M5CF", 4);
  buf[4] = 2;                          // version
  buf[5] = 1;                          // espanol
  buf[6] = 0;                          // BIP44
  const uint32_t lock = device_settings::kTimeout5m;
  buf[7] = lock & 0xff;
  buf[8] = (lock >> 8) & 0xff;
  buf[9] = (lock >> 16) & 0xff;
  buf[10] = (lock >> 24) & 0xff;
  const uint32_t clean = device_settings::kClean10m;
  buf[11] = clean & 0xff;
  buf[12] = (clean >> 8) & 0xff;
  buf[13] = (clean >> 16) & 0xff;
  buf[14] = (clean >> 24) & 0xff;
  TEST_ASSERT_EQUAL_UINT(15, f.write(buf, 15));
  f.flush();
  f.close();

  auto l = device_settings::load();
  TEST_ASSERT_EQUAL_UINT8(1, l.language);
  TEST_ASSERT_EQUAL_UINT32(device_settings::kTimeout5m, l.lockTimeoutMs);
  TEST_ASSERT_EQUAL_UINT32(device_settings::kClean10m, l.seedCleanTimeoutMs);
  // screenCleanEvery hereda el valor por defecto (7) al no existir en v2.
  TEST_ASSERT_EQUAL_UINT8(7, l.screenCleanEvery);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_defaults);
  RUN_TEST(test_valid_rejects_bad);
  RUN_TEST(test_save_load_roundtrip);
  RUN_TEST(test_load_missing_file_returns_defaults);
  RUN_TEST(test_load_legacy_v2);
  return UNITY_END();
}
