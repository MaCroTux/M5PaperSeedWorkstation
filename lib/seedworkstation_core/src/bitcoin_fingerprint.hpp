#pragma once
#include <Arduino.h>
#include "bitcoin_hd.hpp"

namespace bitcoin_fingerprint {
inline bool calculate(const uint16_t* indices, size_t count, uint8_t out[4],
                      const char* passphrase = "") {
  // Reutiliza bitcoin_hd (buffers con wipe y ECC con blinding) en lugar de
  // reconstruir la semilla en un String (S-1/S-2).
  uint8_t seed[64] = {};
  bitcoin_hd::Node masterNode = {};
  bool ok = bitcoin_hd::mnemonic_seed(indices, count, seed, passphrase) &&
            bitcoin_hd::master(seed, masterNode);
  if (ok) bitcoin_hd::fingerprint(masterNode, out);
  bitcoin_hd::wipe(seed, sizeof(seed));
  bitcoin_hd::wipe(&masterNode, sizeof(masterNode));
  return ok;
}

inline bool self_test() {
  uint16_t v[12];
  const uint16_t a = bip39::find_exact("abandon", bip39::Wordlist::English), b = bip39::find_exact("about", bip39::Wordlist::English);
  if (a == bip39::kInvalidWord || b == bip39::kInvalidWord) return false;
  for (size_t i = 0; i < 11; ++i) v[i] = a; v[11] = b;
  uint8_t f[4] = {};
  return calculate(v, 12, f) && f[0] == 0x73 && f[1] == 0xc5 &&
         f[2] == 0xda && f[3] == 0x0a;
}
}  // namespace bitcoin_fingerprint
