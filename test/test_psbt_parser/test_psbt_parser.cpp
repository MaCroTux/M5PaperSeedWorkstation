#include <unity.h>
#include <mbedtls/base64.h>
#include "psbt_parser.hpp"
#include "helpers.hpp"
#include <vector>

void setUp(void) {}
void tearDown(void) {}

static const char kSelfTestPsbt[] =
    "70736274ff"
    "010055020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a914111111111111111111111111111111111111111188ac00000000"
    "00010122e8030000000000001976a914111111111111111111111111111111111111111188ac0000";

void test_hex_val(void) {
  TEST_ASSERT_EQUAL_INT(0, psbt::hexVal('0'));
  TEST_ASSERT_EQUAL_INT(9, psbt::hexVal('9'));
  TEST_ASSERT_EQUAL_INT(10, psbt::hexVal('a'));
  TEST_ASSERT_EQUAL_INT(15, psbt::hexVal('F'));
  TEST_ASSERT_EQUAL_INT(-1, psbt::hexVal('g'));
}

void test_read_varint(void) {
  uint64_t out = 0;
  const uint8_t b1[] = {0x05};
  TEST_ASSERT_EQUAL_UINT(1, psbt::readVarint(b1, 1, out));
  TEST_ASSERT_EQUAL_UINT64(5, out);

  const uint8_t bfd[] = {0xfd, 0x34, 0x12};
  TEST_ASSERT_EQUAL_UINT(3, psbt::readVarint(bfd, 3, out));
  TEST_ASSERT_EQUAL_UINT64(0x1234, out);

  const uint8_t bfe[] = {0xfe, 0x78, 0x56, 0x34, 0x12};
  TEST_ASSERT_EQUAL_UINT(5, psbt::readVarint(bfe, 5, out));
  TEST_ASSERT_EQUAL_UINT64(0x12345678, out);

  // Datos insuficientes.
  const uint8_t short_buf[] = {0xfd, 0x34};
  TEST_ASSERT_EQUAL_UINT(0, psbt::readVarint(short_buf, 2, out));
}

void test_format_sats(void) {
  TEST_ASSERT_EQUAL_STRING("1", psbt::formatSats(100000000ULL).c_str());
  TEST_ASSERT_EQUAL_STRING("0", psbt::formatSats(0).c_str());
  TEST_ASSERT_EQUAL_STRING("1.23456789", psbt::formatSats(123456789ULL).c_str());
  TEST_ASSERT_EQUAL_STRING("1.05", psbt::formatSats(105000000ULL).c_str());
}

void test_script_to_address(void) {
  // P2WPKH: 0014 + 20 bytes.
  uint8_t p2wpkh[22] = {0x00, 0x14};
  TEST_ASSERT_TRUE(psbt::scriptToAddress(p2wpkh, 22).startsWith("bc1q"));

  // OP_RETURN: 0x6a ...
  uint8_t opret[] = {0x6a, 0x01, 0x02};
  TEST_ASSERT_EQUAL_STRING("OP_RETURN", psbt::scriptToAddress(opret, 3).c_str());

  // Script desconocido -> vacio.
  uint8_t unknown[] = {0x01, 0x02};
  TEST_ASSERT_EQUAL_STRING("", psbt::scriptToAddress(unknown, 2).c_str());
}

void test_parse_psbt(void) {
  const auto data = testutil::hex(kSelfTestPsbt);
  psbt::ParsedTx tx;
  TEST_ASSERT_TRUE(psbt::parsePsbt(data, tx));

  TEST_ASSERT_EQUAL_UINT(2, tx.version);
  TEST_ASSERT_EQUAL_UINT(1, tx.inputs.size());
  TEST_ASSERT_EQUAL_UINT(1, tx.outputs.size());
  TEST_ASSERT_EQUAL_UINT64(1000, tx.totalOut);
  TEST_ASSERT_TRUE(tx.inputsComplete);
  TEST_ASSERT_EQUAL_UINT64(1000, tx.totalIn);
  TEST_ASSERT_EQUAL_INT64(0, tx.fee);
  TEST_ASSERT_EQUAL_UINT64(1000, tx.totalPay);
  TEST_ASSERT_EQUAL_UINT64(0, tx.totalChange);
  TEST_ASSERT_TRUE(tx.outputs[0].address.startsWith("1"));
  TEST_ASSERT_TRUE(tx.inputs[0].amountKnown);
  TEST_ASSERT_EQUAL_UINT64(1000, tx.inputs[0].amount);
}

void test_try_parse_psbt_hex(void) {
  const auto data = testutil::hex(kSelfTestPsbt);
  psbt::ParsedTx tx;
  TEST_ASSERT_TRUE(psbt::tryParsePsbt(data, tx));
  TEST_ASSERT_EQUAL_UINT(1, tx.inputs.size());
}

void test_try_parse_psbt_base64(void) {
  const auto raw = testutil::hex(kSelfTestPsbt);
  std::vector<uint8_t> b64(raw.size() * 2);
  size_t olen = 0;
  TEST_ASSERT_EQUAL_INT(0, mbedtls_base64_encode(b64.data(), b64.size(), &olen,
                                                 raw.data(), raw.size()));
  std::vector<uint8_t> encoded(b64.begin(), b64.begin() + olen);

  psbt::ParsedTx tx;
  TEST_ASSERT_TRUE(psbt::tryParsePsbt(encoded, tx));
  TEST_ASSERT_EQUAL_UINT(1, tx.inputs.size());
}

void test_try_parse_invalid(void) {
  const auto data = testutil::hex("deadbeef");
  psbt::ParsedTx tx;
  TEST_ASSERT_FALSE(psbt::tryParsePsbt(data, tx));
}

void test_self_test(void) { TEST_ASSERT_TRUE(psbt::self_test()); }

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_hex_val);
  RUN_TEST(test_read_varint);
  RUN_TEST(test_format_sats);
  RUN_TEST(test_script_to_address);
  RUN_TEST(test_parse_psbt);
  RUN_TEST(test_try_parse_psbt_hex);
  RUN_TEST(test_try_parse_psbt_base64);
  RUN_TEST(test_try_parse_invalid);
  RUN_TEST(test_self_test);
  return UNITY_END();
}
