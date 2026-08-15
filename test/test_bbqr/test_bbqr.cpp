#include <unity.h>
#include "bbqr.hpp"
#include "helpers.hpp"
#include <vector>

void setUp(void) {}
void tearDown(void) {}

void test_base36_two_digits(void) {
  TEST_ASSERT_EQUAL_STRING("00", bbqr::base36TwoDigits(0).c_str());
  TEST_ASSERT_EQUAL_STRING("0Z", bbqr::base36TwoDigits(35).c_str());
  TEST_ASSERT_EQUAL_STRING("10", bbqr::base36TwoDigits(36).c_str());
  TEST_ASSERT_EQUAL_STRING("ZZ", bbqr::base36TwoDigits(1295).c_str());
}

void test_bytes_to_upper_hex(void) {
  uint8_t data[] = {0x00, 0xab, 0xff};
  TEST_ASSERT_EQUAL_STRING("00ABFF",
                           bbqr::bytesToUpperHex(data, 3).c_str());
}

void test_calculate_layout(void) {
  auto l = bbqr::calculateLayout(100, 800);
  TEST_ASSERT_EQUAL_UINT(1, l.totalParts);
  TEST_ASSERT_EQUAL_UINT(100, l.blockSize);

  auto l2 = bbqr::calculateLayout(2000, 800);
  TEST_ASSERT_EQUAL_UINT(3, l2.totalParts);
  TEST_ASSERT_EQUAL_UINT(667, l2.blockSize);

  auto l3 = bbqr::calculateLayout(0, 800);
  TEST_ASSERT_EQUAL_UINT(1, l3.totalParts);
  TEST_ASSERT_EQUAL_UINT(0, l3.blockSize);
}

void test_make_frame(void) {
  const auto data = testutil::hex("deadbeefcafebabe");
  auto layout = bbqr::calculateLayout(data.size(), 800);
  String frame = bbqr::makeFrame(data.data(), data.size(), bbqr::kTypePsbt,
                                 layout.totalParts, 0, layout.blockSize);
  // "B$" + "H" + "P" + "01" + "00" + payload hex.
  TEST_ASSERT_EQUAL_STRING("B$HP0100DEADBEEFCAFEBABE", frame.c_str());
}

void test_frame_split_reconstruct(void) {
  std::vector<uint8_t> data(2000);
  for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i & 0xff);

  auto layout = bbqr::calculateLayout(data.size(), 800);
  std::vector<uint8_t> rebuilt;
  for (uint16_t idx = 0; idx < layout.totalParts; ++idx) {
    String frame = bbqr::makeFrame(data.data(), data.size(), bbqr::kTypeTx,
                                   layout.totalParts, idx, layout.blockSize);
    TEST_ASSERT_TRUE(frame.startsWith("B$HT"));
    // Cabecera de 8 caracteres; el resto es hex.
    const String hex = frame.substring(8);
    TEST_ASSERT_EQUAL_UINT(0, hex.length() % 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
      const int hi = testutil::hexNib(hex.charAt(i));
      const int lo = testutil::hexNib(hex.charAt(i + 1));
      rebuilt.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
  }
  TEST_ASSERT_EQUAL_UINT(data.size(), rebuilt.size());
  TEST_ASSERT_TRUE(testutil::eq(data.data(), rebuilt.data(), data.size()));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_base36_two_digits);
  RUN_TEST(test_bytes_to_upper_hex);
  RUN_TEST(test_calculate_layout);
  RUN_TEST(test_make_frame);
  RUN_TEST(test_frame_split_reconstruct);
  return UNITY_END();
}
