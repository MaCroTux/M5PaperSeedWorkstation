#include <unity.h>
#include "ur_psbt.hpp"
#include "helpers.hpp"
#include <vector>

void setUp(void) {}
void tearDown(void) {}

static const char kSelfTestPsbt[] =
    "70736274ff"
    "010055020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a914111111111111111111111111111111111111111188ac00000000"
    "00010122e8030000000000001976a914111111111111111111111111111111111111111188ac0000";

// Envuelve bytes en una byte string CBOR (major type 2).
static std::vector<uint8_t> cborBytes(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> out;
  const size_t n = data.size();
  if (n < 24) {
    out.push_back(static_cast<uint8_t>(0x40 | n));
  } else if (n <= 0xff) {
    out.push_back(0x58);
    out.push_back(static_cast<uint8_t>(n));
  } else if (n <= 0xffff) {
    out.push_back(0x59);
    out.push_back(static_cast<uint8_t>(n >> 8));
    out.push_back(static_cast<uint8_t>(n & 0xff));
  }
  out.insert(out.end(), data.begin(), data.end());
  return out;
}

// Codifica bytes a bytewords "minimal" (primera + ultima letra).
static String bytewords(const std::vector<uint8_t>& data) {
  String s;
  s.reserve(data.size() * 2);
  for (uint8_t b : data) {
    s += ur::kWordlist[b * 4];
    s += ur::kWordlist[b * 4 + 3];
  }
  return s;
}

void test_minimal_to_index(void) {
  TEST_ASSERT_EQUAL_INT(0, ur::minimalToIndex('a', 'e'));   // "able"
  TEST_ASSERT_EQUAL_INT(1, ur::minimalToIndex('a', 'd'));   // "acid"
  TEST_ASSERT_EQUAL_INT(2, ur::minimalToIndex('a', 'o'));   // "also"
  TEST_ASSERT_EQUAL_INT(-1, ur::minimalToIndex('x', 'x'));
}

void test_decode_bytewords(void) {
  std::vector<uint8_t> out;
  TEST_ASSERT_TRUE(ur::decodeBytewords("aead", out));
  TEST_ASSERT_EQUAL_UINT(2, out.size());
  TEST_ASSERT_EQUAL_UINT8(0, out[0]);
  TEST_ASSERT_EQUAL_UINT8(1, out[1]);

  // Longitud impar -> falla.
  TEST_ASSERT_FALSE(ur::decodeBytewords("a", out));
  // Caracter invalido -> falla.
  TEST_ASSERT_FALSE(ur::decodeBytewords("xx", out));
}

void test_unwrap_cbor_bytes(void) {
  std::vector<uint8_t> out;
  // Byte string de longitud 3 (0x43 01 02 03).
  const std::vector<uint8_t> in = {0x43, 0x01, 0x02, 0x03};
  TEST_ASSERT_TRUE(ur::unwrapCborBytes(in, out));
  TEST_ASSERT_EQUAL_UINT(3, out.size());
  TEST_ASSERT_EQUAL_UINT8(0x02, out[1]);

  // Major type incorrecto (0x00 = uint) -> falla.
  const std::vector<uint8_t> bad = {0x00, 0x01};
  TEST_ASSERT_FALSE(ur::unwrapCborBytes(bad, out));

  // Longitud 24 (0x58 0x18 + 24 bytes).
  std::vector<uint8_t> in24 = {0x58, 0x18};
  for (int i = 0; i < 24; ++i) in24.push_back(static_cast<uint8_t>(i));
  TEST_ASSERT_TRUE(ur::unwrapCborBytes(in24, out));
  TEST_ASSERT_EQUAL_UINT(24, out.size());
}

void test_decode_crypto_psbt(void) {
  const auto psbt = testutil::hex(kSelfTestPsbt);
  String ur = "ur:crypto-psbt/";
  ur += bytewords(cborBytes(psbt));

  std::vector<uint8_t> decoded;
  TEST_ASSERT_TRUE(ur::decodeCryptoPsbt(ur, decoded));
  TEST_ASSERT_EQUAL_UINT(psbt.size(), decoded.size());
  TEST_ASSERT_TRUE(testutil::eq(psbt.data(), decoded.data(), psbt.size()));
}

void test_decode_crypto_psbt_lowercase(void) {
  const auto psbt = testutil::hex(kSelfTestPsbt);
  String ur = "UR:CRYPTO-PSBT/";
  ur += bytewords(cborBytes(psbt));
  std::vector<uint8_t> decoded;
  TEST_ASSERT_TRUE(ur::decodeCryptoPsbt(ur, decoded));
  TEST_ASSERT_EQUAL_UINT(psbt.size(), decoded.size());
}

void test_decode_crypto_psbt_invalid(void) {
  std::vector<uint8_t> decoded;
  // Sin prefijo "crypto-psbt/".
  TEST_ASSERT_FALSE(ur::decodeCryptoPsbt("ur:bitcoin/xyz", decoded));
  // Magic PSBT incorrecto.
  String ur = "ur:crypto-psbt/";
  ur += bytewords(cborBytes({0xde, 0xad, 0xbe, 0xef, 0xff}));
  TEST_ASSERT_FALSE(ur::decodeCryptoPsbt(ur, decoded));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_minimal_to_index);
  RUN_TEST(test_decode_bytewords);
  RUN_TEST(test_unwrap_cbor_bytes);
  RUN_TEST(test_decode_crypto_psbt);
  RUN_TEST(test_decode_crypto_psbt_lowercase);
  RUN_TEST(test_decode_crypto_psbt_invalid);
  return UNITY_END();
}
