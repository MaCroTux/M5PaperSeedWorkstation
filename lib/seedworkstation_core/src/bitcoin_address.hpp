#pragma once

#include "bitcoin_hd.hpp"

namespace bitcoin_address {

inline void hash160(const uint8_t* data, size_t length, uint8_t out[20]) {
  uint8_t sha[32] = {};
  if (mbedtls_sha256_ret(data, length, sha, 0) == 0)
    ripemd160_min::hash(sha, sizeof(sha), out);
  bitcoin_hd::wipe(sha, sizeof(sha));
}

inline String base58_address(uint8_t prefix, const uint8_t hash[20]) {
  uint8_t payload[25] = {}, first[32] = {}, second[32] = {}, digits[40] = {};
  payload[0] = prefix; memcpy(payload + 1, hash, 20);
  if (mbedtls_sha256_ret(payload, 21, first, 0) != 0 ||
      mbedtls_sha256_ret(first, 32, second, 0) != 0) return String();
  memcpy(payload + 21, second, 4); size_t count = 1;
  for (uint8_t byte : payload) {
    uint32_t carry = byte;
    for (size_t j = 0; j < count; ++j) {
      carry += static_cast<uint32_t>(digits[j]) << 8;
      digits[j] = carry % 58; carry /= 58;
    }
    while (carry) { digits[count++] = carry % 58; carry /= 58; }
  }
  static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  String result; size_t zeroes = 0;
  while (zeroes < sizeof(payload) && payload[zeroes] == 0) { result += '1'; ++zeroes; }
  while (count && digits[count - 1] == 0) --count;
  while (count) result += alphabet[digits[--count]];
  bitcoin_hd::wipe(payload, sizeof(payload)); bitcoin_hd::wipe(first, sizeof(first));
  bitcoin_hd::wipe(second, sizeof(second)); bitcoin_hd::wipe(digits, sizeof(digits));
  return result;
}

inline uint32_t polymod(const uint8_t* values, size_t length) {
  static const uint32_t generator[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
                                        0x3d4233dd, 0x2a1462b3};
  uint32_t chk = 1;
  for (size_t i = 0; i < length; ++i) {
    const uint8_t top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ values[i];
    for (uint8_t j = 0; j < 5; ++j) if ((top >> j) & 1) chk ^= generator[j];
  }
  return chk;
}

inline String segwit_address(uint8_t version, const uint8_t* program, size_t length) {
  if ((version != 0 && version != 1) || (length != 20 && length != 32)) return String();
  uint8_t values[80] = {}, expanded[5] = {3, 3, 0, 2, 3}; // "bc" HRP expansion
  size_t valueCount = 0; values[valueCount++] = version;
  uint32_t accumulator = 0; uint8_t bits = 0;
  for (size_t i = 0; i < length; ++i) {
    accumulator = (accumulator << 8) | program[i]; bits += 8;
    while (bits >= 5) { bits -= 5; values[valueCount++] = (accumulator >> bits) & 31; }
  }
  if (bits) values[valueCount++] = (accumulator << (5 - bits)) & 31;
  uint8_t checkInput[96] = {}; size_t checkLength = 0;
  memcpy(checkInput, expanded, sizeof(expanded)); checkLength += sizeof(expanded);
  memcpy(checkInput + checkLength, values, valueCount); checkLength += valueCount;
  memset(checkInput + checkLength, 0, 6); checkLength += 6;
  const uint32_t constant = version == 0 ? 1 : 0x2bc830a3UL;
  const uint32_t check = polymod(checkInput, checkLength) ^ constant;
  static const char charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  String result = "bc1";
  for (size_t i = 0; i < valueCount; ++i) result += charset[values[i]];
  for (uint8_t i = 0; i < 6; ++i) result += charset[(check >> (5 * (5 - i))) & 31];
  bitcoin_hd::wipe(values, sizeof(values)); bitcoin_hd::wipe(checkInput, sizeof(checkInput));
  return result;
}

inline bool derive(const uint16_t* words, size_t count, uint32_t purpose,
                   uint8_t change, uint32_t index, String& address,
                   const char* passphrase = "") {
  if (change > 1 || index >= 0x80000000UL) return false;
  bitcoin_hd::Node account = {}, branch = {}, child = {};
  uint8_t pub[33] = {}, keyHash[20] = {};
  bool ok = bitcoin_hd::account_node(words, count, purpose, account, passphrase) &&
      bitcoin_hd::derive_normal(account, change, branch) &&
      bitcoin_hd::derive_normal(branch, index, child) && bitcoin_hd::public_key(child, pub);
  if (ok && purpose == 44) { hash160(pub, 33, keyHash); address = base58_address(0, keyHash); }
  else if (ok && purpose == 49) {
    hash160(pub, 33, keyHash); uint8_t redeem[22] = {0, 20}; memcpy(redeem + 2, keyHash, 20);
    hash160(redeem, sizeof(redeem), keyHash); address = base58_address(5, keyHash);
    bitcoin_hd::wipe(redeem, sizeof(redeem));
  } else if (ok && purpose == 84) { hash160(pub, 33, keyHash); address = segwit_address(0, keyHash, 20); }
  else ok = false;
  ok = ok && address.length(); bitcoin_hd::wipe(&account, sizeof(account));
  bitcoin_hd::wipe(&branch, sizeof(branch)); bitcoin_hd::wipe(&child, sizeof(child));
  bitcoin_hd::wipe(pub, sizeof(pub)); bitcoin_hd::wipe(keyHash, sizeof(keyHash));
  return ok;
}

// Deriva una direccion a partir de un nodo de cuenta ya calculado (evita
// repetir el PBKDF2 de la semilla por cada direccion).
inline bool derive_from_account(const bitcoin_hd::Node& account, uint32_t purpose,
                                uint8_t change, uint32_t index, String& address) {
  if (change > 1 || index >= 0x80000000UL) return false;
  bitcoin_hd::Node branch = {}, child = {};
  uint8_t pub[33] = {}, keyHash[20] = {};
  bool ok = bitcoin_hd::derive_normal(account, change, branch) &&
      bitcoin_hd::derive_normal(branch, index, child) && bitcoin_hd::public_key(child, pub);
  if (ok && purpose == 44) { hash160(pub, 33, keyHash); address = base58_address(0, keyHash); }
  else if (ok && purpose == 49) {
    hash160(pub, 33, keyHash); uint8_t redeem[22] = {0, 20}; memcpy(redeem + 2, keyHash, 20);
    hash160(redeem, sizeof(redeem), keyHash); address = base58_address(5, keyHash);
    bitcoin_hd::wipe(redeem, sizeof(redeem));
  } else if (ok && purpose == 84) { hash160(pub, 33, keyHash); address = segwit_address(0, keyHash, 20); }
  else ok = false;
  ok = ok && address.length();
  bitcoin_hd::wipe(&branch, sizeof(branch)); bitcoin_hd::wipe(&child, sizeof(child));
  bitcoin_hd::wipe(pub, sizeof(pub)); bitcoin_hd::wipe(keyHash, sizeof(keyHash));
  return ok;
}

inline bool test_words(uint16_t words[12]) {
  const uint16_t abandon = bip39::find_exact("abandon");
  const uint16_t about = bip39::find_exact("about");
  if (abandon == bip39::kInvalidWord || about == bip39::kInvalidWord) return false;
  for (uint8_t i = 0; i < 11; ++i) words[i] = abandon;
  words[11] = about; return true;
}

inline bool self_test_bip84() {
  uint16_t words[12];
  if (!test_words(words)) return false;
  String nativeSegwit;
  const bool ok84 = derive(words, 12, 84, 0, 0, nativeSegwit) &&
      nativeSegwit == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
  nativeSegwit = ""; bitcoin_hd::wipe(words, sizeof(words)); return ok84;
}

inline bool self_test() {
  return self_test_bip84();
}

}  // namespace bitcoin_address
