#include <unity.h>
#include "tx_sign.hpp"
#include "helpers.hpp"
#include "krux_vectors.h"
#include "krux_p2pkh.h"

void setUp(void) { host::seedRandom(0x12345678u); }

void tearDown(void) {}

void test_hmac_sha256_rfc4231(void) {
  // RFC4231 Test Case 1.
  uint8_t key[20];
  memset(key, 0x0b, sizeof(key));
  const char* data = "Hi There";
  uint8_t out[32] = {};
  TEST_ASSERT_TRUE(tx_sign::hmacSha256(key, 20, reinterpret_cast<const uint8_t*>(data),
                                       8, out));
  const auto expected = testutil::hex(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 32));
}

void test_sha256d(void) {
  // double-SHA256 de cadena vacia.
  uint8_t out[32] = {};
  tx_sign::sha256d(nullptr, 0, out);
  const auto expected = testutil::hex(
      "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
  TEST_ASSERT_TRUE(testutil::eq(out, expected.data(), 32));
}

void test_der_roundtrip(void) {
  uint8_t r[32] = {};
  uint8_t s[32] = {};
  for (int i = 0; i < 32; ++i) {
    r[i] = static_cast<uint8_t>(i + 1);
    s[i] = static_cast<uint8_t>(0xff - i);
  }
  uint8_t der[73] = {};
  const size_t n = tx_sign::derEncode(r, s, der);
  TEST_ASSERT_GREATER_THAN(0, n);

  uint8_t rs[64] = {};
  TEST_ASSERT_TRUE(tx_sign::derDecode(der, n, rs));
  TEST_ASSERT_TRUE(testutil::eq(rs, r, 32));
  TEST_ASSERT_TRUE(testutil::eq(rs + 32, s, 32));
}

void test_script_purpose(void) {
  uint32_t purpose = 0;

  uint8_t p2wpkh[22] = {0x00, 0x14};
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2wpkh, 22, purpose));
  TEST_ASSERT_EQUAL_UINT(84, purpose);

  uint8_t p2pkh[25] = {0x76, 0xa9, 0x14};
  p2pkh[23] = 0x88;
  p2pkh[24] = 0xac;
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2pkh, 25, purpose));
  TEST_ASSERT_EQUAL_UINT(44, purpose);

  uint8_t p2sh[23] = {0xa9, 0x14};
  p2sh[22] = 0x87;
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2sh, 23, purpose));
  TEST_ASSERT_EQUAL_UINT(49, purpose);

  uint8_t p2tr[34] = {0x51, 0x20};
  TEST_ASSERT_TRUE(tx_sign::scriptPurpose(p2tr, 34, purpose));
  TEST_ASSERT_EQUAL_UINT(86, purpose);

  uint8_t unknown[2] = {0x01, 0x02};
  TEST_ASSERT_FALSE(tx_sign::scriptPurpose(unknown, 2, purpose));
}

void test_sign_deterministic(void) {
  static const uint8_t key[32] = {
      0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57,
      0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
      0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21};
  static const uint8_t msg[32] = {
      0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1, 0xD6,
      0x94, 0xF4, 0x1F, 0xC7, 0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
      0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF};

  uint8_t sig1[64] = {}, sig2[64] = {};
  TEST_ASSERT_TRUE(tx_sign::sign(key, msg, sig1));
  TEST_ASSERT_TRUE(tx_sign::sign(key, msg, sig2));
  TEST_ASSERT_TRUE(testutil::eq(sig1, sig2, 64));  // determinismo RFC6979
}

void test_self_test(void) { TEST_ASSERT_TRUE(tx_sign::self_test()); }

// Valida la firma completa contra los vectores de Krux (embit): P2WPKH y
// P2SH-P2WPKH con la semilla "abandon x11 + about" (sin passphrase).
static void signAndCheck(const char* psbtHex, const char* expectedPubHex,
                         const char* expectedSighashHex, bool checkScriptSig,
                         const char* redeemHex) {
  const std::vector<uint8_t> raw = testutil::hex(psbtHex);
  psbt::ParsedTx tx;
  TEST_ASSERT_TRUE(psbt::tryParsePsbt(raw, tx));

  std::vector<uint8_t> signedTx;
  std::vector<tx_sign::InputSig> sigs;
  const bool ok = tx_sign::signSegwitP2wpkh(tx, KRUX_WORDS, 12, "", signedTx,
                                            nullptr, &sigs);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_TRUE(sigs.size() == tx.inputs.size());

  // La pubkey derivada y el sighash BIP143 deben coincidir byte a byte con embit.
  const std::vector<uint8_t> expPub = testutil::hex(expectedPubHex);
  const std::vector<uint8_t> expSighash = testutil::hex(expectedSighashHex);
  TEST_ASSERT_TRUE(testutil::eq(sigs[0].pub, expPub.data(), 33));
  TEST_ASSERT_TRUE(testutil::eq(sigs[0].sighash, expSighash.data(), 32));

  // La firma (nonce RFC6979) puede diferir de embit por el "low-R grinding",
  // pero debe ser valida: signSegwitP2wpkh ya la autoverifica antes de devolver.
  if (checkScriptSig) {
    const std::vector<uint8_t> redeem = testutil::hex(redeemHex);
    TEST_ASSERT_TRUE(redeem.size() + 1 == sigs[0].scriptSigLen);
    TEST_ASSERT_EQUAL_UINT(0x16, sigs[0].scriptSig[0]);
    TEST_ASSERT_TRUE(testutil::eq(sigs[0].scriptSig + 1, redeem.data(), redeem.size()));
  }
}

void test_krux_p2wpkh(void) {
  signAndCheck(P2WPKH_PSBT_HEX, P2WPKH_PUB_HEX, P2WPKH_SIGHASH_HEX, false, nullptr);
}

void test_krux_p2pkh(void) {
  const std::vector<uint8_t> raw = testutil::hex(P2PKH_PSBT_HEX);
  psbt::ParsedTx tx;
  TEST_ASSERT_TRUE(psbt::tryParsePsbt(raw, tx));
  TEST_ASSERT_TRUE(tx.inputs.size() == 3);

  std::vector<uint8_t> signedTx;
  std::vector<tx_sign::InputSig> sigs;
  TEST_ASSERT_TRUE(tx_sign::signLegacyP2pkh(tx, KRUX_WORDS, 12, "", signedTx, nullptr, &sigs));
  TEST_ASSERT_TRUE(sigs.size() == 3);

  // Los sighash legacy y la pubkey deben coincidir con embit.
  const char* expSh[3] = {P2PKH_SIGHASH0_HEX, P2PKH_SIGHASH1_HEX, P2PKH_SIGHASH2_HEX};
  for (int i = 0; i < 3; ++i) {
    const auto sh = testutil::hex(expSh[i]);
    TEST_ASSERT_TRUE(testutil::eq(sigs[i].sighash, sh.data(), 32));
  }
  const auto pub = testutil::hex(P2PKH_PUB_HEX);
  for (int i = 0; i < 3; ++i) {
    TEST_ASSERT_TRUE(testutil::eq(sigs[i].pub, pub.data(), 33));
    // scriptSig = push(sig) || push(pubkey): byte 0 = len(sig), luego sig, 0x21, pub.
    TEST_ASSERT_TRUE(sigs[i].scriptSig[0] == sigs[i].derLen);
    TEST_ASSERT_TRUE(sigs[i].scriptSig[1 + sigs[i].derLen] == 0x21);
    TEST_ASSERT_TRUE(sigs[i].scriptSigLen == 1 + sigs[i].derLen + 1 + 33);
  }
}

void test_krux_p2sh_p2wpkh(void) {
  signAndCheck(P2SH_P2WPKH_PSBT_HEX, P2SH_P2WPKH_PUB_HEX, P2SH_P2WPKH_SIGHASH_HEX,
               true, P2SH_P2WPKH_REDEEM_HEX);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_hmac_sha256_rfc4231);
  RUN_TEST(test_sha256d);
  RUN_TEST(test_der_roundtrip);
  RUN_TEST(test_script_purpose);
  RUN_TEST(test_sign_deterministic);
  RUN_TEST(test_self_test);
  RUN_TEST(test_krux_p2wpkh);
  RUN_TEST(test_krux_p2sh_p2wpkh);
  RUN_TEST(test_krux_p2pkh);
  return UNITY_END();
}
