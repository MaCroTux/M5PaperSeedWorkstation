#include <unity.h>
#include "ripemd160_min.hpp"
#include "helpers.hpp"

void setUp(void) {}
void tearDown(void) {}

void test_ripemd160_abc(void) {
  const char* msg = "abc";
  uint8_t out[20] = {};
  ripemd160_min::hash(reinterpret_cast<const uint8_t*>(msg), 3, out);
  const auto expected = testutil::hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 20));
}

void test_ripemd160_empty(void) {
  uint8_t out[20] = {};
  ripemd160_min::hash(nullptr, 0, out);
  const auto expected = testutil::hex("9c1185a5c5e9fc54612808977ee8f548b2258d31");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 20));
}

void test_ripemd160_message_digest(void) {
  const char* msg = "message digest";
  uint8_t out[20] = {};
  ripemd160_min::hash(reinterpret_cast<const uint8_t*>(msg), 14, out);
  const auto expected = testutil::hex("5d0689ef49d2fae572b881b123a85ffa21595f36");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 20));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ripemd160_abc);
  RUN_TEST(test_ripemd160_empty);
  RUN_TEST(test_ripemd160_message_digest);
  return UNITY_END();
}
