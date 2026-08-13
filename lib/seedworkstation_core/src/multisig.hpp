#pragma once
#include <Arduino.h>
#include "bitcoin_hd.hpp"
#include "psbt_parser.hpp"
#include "tx_sign.hpp"
#include <vector>

// Soporte de Bitcoin Multisig moderno: PSBT (BIP174) + BIP48 + P2WSH +
// sortedmulti, interoperable con Sparrow Wallet.
//
// Alcance v1: P2WSH wsh(sortedmulti(...)), ECDSA/secp256k1, 2-of-2/2-of-3/3-of-3.
// No se implementa Taproot multisig, MuSig2 ni miniscript.
//
// Seguridad: las claves privadas nunca se serializan, loguean ni se exportan.

namespace multisig {

constexpr size_t kMaxKeys = 16;

struct SeedCandidate {
  const uint16_t* indices;
  uint8_t count;
  const char* passphrase;
};

struct MultisigScript {
  bool valid = false;
  uint8_t m = 0;
  uint8_t n = 0;
  uint8_t keys[kMaxKeys][33] = {};
};

// Parsea wsh(sortedmulti(...)). Devuelve M, N y las pubkeys (en orden).
inline bool parseSortedMulti(const uint8_t* script, size_t len, MultisigScript& out) {
  out = MultisigScript{};
  if (len < 4) return false;
  if (script[0] < 0x51 || script[0] > 0x60) return false;
  out.m = script[0] - 0x50;
  size_t i = 1;
  out.n = 0;
  while (i < len && out.n < kMaxKeys) {
    if (script[i] == 0x21 && i + 34 <= len) {
      memcpy(out.keys[out.n], script + i + 1, 33);
      out.n++;
      i += 34;
    } else {
      break;
    }
  }
  if (i >= len) return false;
  if (script[i] < 0x51 || script[i] > 0x60) return false;
  if (script[i] - 0x50 != out.n) return false;
  i++;
  if (i >= len || script[i] != 0xae) return false;
  i++;
  if (i != len) return false;
  if (out.m == 0 || out.n == 0 || out.m > out.n) return false;
  // Verifica orden lexicografico (sortedmulti).
  for (uint8_t k = 1; k < out.n; ++k)
    if (memcmp(out.keys[k - 1], out.keys[k], 33) > 0) return false;
  out.valid = true;
  return true;
}

struct MultisigInfo {
  bool isMultisig = false;
  bool allP2wsh = false;
  uint8_t m = 0;
  uint8_t n = 0;
  size_t inputs = 0;
};

// Detecta si TODOS los inputs son P2WSH sortedmulti con la misma politica M/N.
inline bool detect(const psbt::ParsedTx& tx, MultisigInfo& info) {
  info = MultisigInfo{};
  if (tx.inputs.empty()) return false;
  uint8_t firstM = 0, firstN = 0;
  bool haveFirst = false;
  for (const auto& in : tx.inputs) {
    // El scriptPubKey del UTXO debe ser P2WSH: 0x00 0x20 <32 bytes>.
    if (in.utxoScriptLen != 34 || in.utxoScript[0] != 0x00 || in.utxoScript[1] != 0x20) {
      Serial.printf("[MULTISIG] input no P2WSH (len=%u)\n",
                    static_cast<unsigned>(in.utxoScriptLen));
      return false;
    }
    MultisigScript ms;
    if (!parseSortedMulti(in.witnessScript, in.witnessScriptLen, ms)) {
      Serial.println("[MULTISIG] witnessScript no es sortedmulti");
      return false;
    }
    // P2WSH: el scriptPubKey contiene el SHA256 (UNA sola ronda) del witnessScript.
    uint8_t h[32] = {};
    mbedtls_sha256_ret(in.witnessScript, in.witnessScriptLen, h, 0);
    if (memcmp(h, in.utxoScript + 2, 32) != 0) {
      Serial.println("[MULTISIG] witnessScript hash mismatch");
      return false;
    }
    Serial.printf("[MULTISIG] detected P2WSH policy=%u-of-%u pubkeys=%u\n",
                  ms.m, ms.n, ms.n);
    if (!haveFirst) { firstM = ms.m; firstN = ms.n; haveFirst = true; }
    else if (ms.m != firstM || ms.n != firstN) return false;
  }
  info.isMultisig = true;
  info.allP2wsh = true;
  info.m = firstM;
  info.n = firstN;
  info.inputs = tx.inputs.size();
  return true;
}

// Busca en una lista de partial_sigs la firma de una pubkey determinada.
inline bool findSig(const std::vector<psbt::PartialSig>& sigs, const uint8_t pub[33],
                    const uint8_t** outSig, size_t* outLen) {
  for (const auto& s : sigs) {
    if (memcmp(s.pub, pub, 33) == 0) {
      *outSig = s.sig;
      *outLen = s.sigLen;
      return true;
    }
  }
  return false;
}

// Recorre las seeds del Vault y, para cada pubkey del witnessScript con
// derivacion, comprueba fingerprint + pubkey derivada. Devuelve en "matches"
// por pubkey el indice de seed que puede firmarla (-1 si ninguna).
inline void matchSigners(const psbt::TxInput& in, const MultisigScript& ms,
                         const std::vector<SeedCandidate>& seeds,
                         int8_t* matchByKey) {
  for (uint8_t k = 0; k < ms.n; ++k) matchByKey[k] = -1;
  // Localiza la derivacion (signers) que corresponde a cada pubkey del script.
  for (uint8_t k = 0; k < ms.n; ++k) {
    for (const auto& si : in.signers) {
      if (memcmp(si.pub, ms.keys[k], 33) != 0) continue;
      for (size_t s = 0; s < seeds.size(); ++s) {
        uint8_t key[32] = {}, pub[33] = {};
        if (tx_sign::deriveKey(seeds[s].indices, seeds[s].count, si.fpr, si.path,
                               seeds[s].passphrase, key, pub, false)) {
          const bool ok = memcmp(pub, ms.keys[k], 33) == 0;
          bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(pub, 33);
          if (ok) {
            matchByKey[k] = static_cast<int8_t>(s);
            Serial.printf("[MULTISIG] signer fingerprint=%02X%02X%02X%02X -> Vault match, derived pubkey OK\n",
                          si.fpr[0], si.fpr[1], si.fpr[2], si.fpr[3]);
            break;
          }
        }
      }
      break;  // ya se encontro la derivacion para esta pubkey
    }
  }
}

// Reconstruye un PSBT BIP174 a partir del parseo (con las partial_sigs incluidas).
inline void buildPsbt(const psbt::ParsedTx& tx, const std::vector<std::vector<psbt::PartialSig>>& extraSigs,
                      std::vector<uint8_t>& out) {
  std::vector<uint8_t> unsignedTx;
  tx_sign::serializeUnsignedTx(tx, unsignedTx);

  out.clear();
  const uint8_t magic[5] = {0x70, 0x73, 0x62, 0x74, 0xff};
  out.insert(out.end(), magic, magic + 5);

  // Mapa global: key 0x00 = unsigned tx.
  out.push_back(0x01); out.push_back(0x00);
  tx_sign::pushVarint(out, unsignedTx.size());
  out.insert(out.end(), unsignedTx.begin(), unsignedTx.end());
  out.push_back(0x00);

  // Mapas de entrada.
  for (size_t idx = 0; idx < tx.inputs.size(); ++idx) {
    const auto& in = tx.inputs[idx];

    // witness UTXO: key 0x01 = amount(8) + scriptPubKey(varint+bytes).
    if (in.amountKnown) {
      std::vector<uint8_t> v;
      for (int b = 0; b < 8; ++b) v.push_back((in.amount >> (8 * b)) & 0xff);
      tx_sign::pushVarint(v, in.utxoScriptLen);
      v.insert(v.end(), in.utxoScript, in.utxoScript + in.utxoScriptLen);
      out.push_back(0x01); out.push_back(0x01);
      tx_sign::pushVarint(out, v.size());
      out.insert(out.end(), v.begin(), v.end());
    }

    // BIP32 derivations: key 0x06 + pubkey(33), value = fpr(4) + path.
    for (const auto& si : in.signers) {
      std::vector<uint8_t> key = {0x06};
      key.insert(key.end(), si.pub, si.pub + 33);
      std::vector<uint8_t> v;
      v.insert(v.end(), si.fpr, si.fpr + 4);
      for (uint32_t p : si.path)
        for (int b = 0; b < 4; ++b) v.push_back((p >> (8 * b)) & 0xff);
      tx_sign::pushVarint(out, key.size());
      out.insert(out.end(), key.begin(), key.end());
      tx_sign::pushVarint(out, v.size());
      out.insert(out.end(), v.begin(), v.end());
    }

    // witnessScript: key 0x05.
    if (in.witnessScriptLen) {
      out.push_back(0x01); out.push_back(0x05);
      tx_sign::pushVarint(out, in.witnessScriptLen);
      out.insert(out.end(), in.witnessScript, in.witnessScript + in.witnessScriptLen);
    }

    // partial_sigs: key 0x02 + pubkey(33), value = signature. No sobrescribir.
    {
      std::vector<psbt::PartialSig> all = in.partialSigs;
      for (const auto& s : extraSigs[idx]) all.push_back(s);
      for (const auto& s : all) {
        std::vector<uint8_t> key = {0x02};
        key.insert(key.end(), s.pub, s.pub + 33);
        tx_sign::pushVarint(out, key.size());
        out.insert(out.end(), key.begin(), key.end());
        tx_sign::pushVarint(out, s.sigLen);
        out.insert(out.end(), s.sig, s.sig + s.sigLen);
      }
    }
    out.push_back(0x00);
  }

  // Mapas de salida (vacios en la PSBT parcial: Sparrow re-deriva el cambio).
  for (size_t i = 0; i < tx.outputs.size(); ++i) out.push_back(0x00);
}

struct SignResult {
  bool ok = false;
  bool finalized = false;
  uint8_t totalSigs = 0;    // firmas presentes despues de firmar (por input)
  uint8_t needed = 0;       // threshold M
  uint8_t vaultSigners = 0; // numero de keys del Vault que firmaron
  std::vector<uint8_t> partialPsbt;
  std::vector<uint8_t> finalizedPsbt;
  std::vector<uint8_t> rawTx;
};

// Firma una PSBT multisig. Reune todas las seeds del Vault en una sola operacion,
// anade partial_sigs y, si se alcanza el threshold, finaliza y extrae la raw tx.
inline SignResult signMultisig(const psbt::ParsedTx& tx,
                               const std::vector<SeedCandidate>& seeds) {
  SignResult r;
  MultisigInfo info;
  if (!detect(tx, info)) return r;
  r.needed = info.m;

  // Firmas extra por input (clave -> sig). Indice por pubkey en el script.
  std::vector<std::vector<psbt::PartialSig>> extraSigs(tx.inputs.size());

  for (size_t idx = 0; idx < tx.inputs.size(); ++idx) {
    const auto& in = tx.inputs[idx];
    MultisigScript ms;
    if (!parseSortedMulti(in.witnessScript, in.witnessScriptLen, ms)) return r;
    if (!in.amountKnown) return r;

    int8_t matchByKey[kMaxKeys];
    matchSigners(in, ms, seeds, matchByKey);

    // Cuenta firmas ya presentes.
    uint8_t present = 0;
    for (uint8_t k = 0; k < ms.n; ++k) {
      const uint8_t* s; size_t sl;
      if (findSig(in.partialSigs, ms.keys[k], &s, &sl)) present++;
    }
    r.totalSigs = present;

    // Firma con las keys del Vault disponibles hasta alcanzar el threshold.
    for (uint8_t k = 0; k < ms.n && present < ms.m; ++k) {
      const int8_t seedIdx = matchByKey[k];
      if (seedIdx < 0) continue;
      const uint8_t* s; size_t sl;
      if (findSig(in.partialSigs, ms.keys[k], &s, &sl)) continue;  // ya firmada

      uint8_t key[32] = {}, pub[33] = {};
      // Busca la derivacion para esta pubkey concreta.
      const psbt::SignerInfo* target = nullptr;
      for (const auto& sgn : in.signers) {
        if (memcmp(sgn.pub, ms.keys[k], 33) == 0) { target = &sgn; break; }
      }
      if (!target || !tx_sign::deriveKey(seeds[seedIdx].indices, seeds[seedIdx].count,
                                          target->fpr, target->path,
                                          seeds[seedIdx].passphrase, key, pub, false))
        { bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(pub, 33); continue; }
      if (memcmp(pub, ms.keys[k], 33) != 0) {
        Serial.println("[MULTISIG] SIGNER VERIFICATION FAILED");
        bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(pub, 33); continue;
      }

      uint8_t sighash[32] = {};
      if (!tx_sign::sighashSegwit(tx, idx, in.witnessScript, in.witnessScriptLen,
                                  in.amount, sighash)) {
        bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(sighash, 32); continue;
      }
      uint8_t rs[64] = {};
      if (!tx_sign::sign(key, sighash, rs)) {
        bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(sighash, 32); bitcoin_hd::wipe(rs, 64);
        continue;
      }
      if (!tx_sign::verify(pub, sighash, rs)) {
        Serial.println("[MULTISIG] SELF VERIFY FAILED");
        bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(pub, 33);
        bitcoin_hd::wipe(sighash, 32); bitcoin_hd::wipe(rs, 64);
        continue;
      }
      psbt::PartialSig ps;
      memcpy(ps.pub, ms.keys[k], 33);
      ps.sigLen = tx_sign::derEncode(rs, rs + 32, ps.sig);
      ps.sig[ps.sigLen++] = tx_sign::kSighashAll;
      extraSigs[idx].push_back(ps);
      present++;
      r.vaultSigners++;
      Serial.printf("[MULTISIG] signing input %u with signer %d -> OK\n",
                    static_cast<unsigned>(idx), static_cast<int>(k));
      bitcoin_hd::wipe(key, 32); bitcoin_hd::wipe(pub, 33);
      bitcoin_hd::wipe(sighash, 32); bitcoin_hd::wipe(rs, 64);
    }
    r.totalSigs = present;
  }

  r.ok = true;
  if (r.totalSigs >= r.needed) {
    r.finalized = true;
    // Construye el witness final de cada input y extrae la raw tx.
    std::vector<std::vector<std::vector<uint8_t>>> witnesses(tx.inputs.size());
    for (size_t idx = 0; idx < tx.inputs.size(); ++idx) {
      const auto& in = tx.inputs[idx];
      MultisigScript ms;
      parseSortedMulti(in.witnessScript, in.witnessScriptLen, ms);
      std::vector<psbt::PartialSig> all = in.partialSigs;
      for (const auto& s : extraSigs[idx]) all.push_back(s);
      // Stack: [empty] + sigs en orden de pubkey + witnessScript.
      witnesses[idx].push_back(std::vector<uint8_t>());  // null para CHECKMULTISIG
      for (uint8_t k = 0; k < ms.n; ++k) {
        for (const auto& s : all)
          if (memcmp(s.pub, ms.keys[k], 33) == 0)
            witnesses[idx].push_back(std::vector<uint8_t>(s.sig, s.sig + s.sigLen));
      }
      witnesses[idx].push_back(std::vector<uint8_t>(
          in.witnessScript, in.witnessScript + in.witnessScriptLen));
    }

    // Raw tx segwit.
    std::vector<uint8_t>& out = r.rawTx;
    for (int b = 0; b < 4; ++b) out.push_back((tx.version >> (8 * b)) & 0xff);
    out.push_back(0x00); out.push_back(0x01);  // segwit marker + flag
    tx_sign::pushVarint(out, tx.inputs.size());
    for (const auto& in : tx.inputs) {
      out.insert(out.end(), in.prevTxid, in.prevTxid + 32);
      for (int b = 0; b < 4; ++b) out.push_back((in.prevVout >> (8 * b)) & 0xff);
      out.push_back(0x00);
      for (int b = 0; b < 4; ++b) out.push_back((in.sequence >> (8 * b)) & 0xff);
    }
    tx_sign::pushVarint(out, tx.outputs.size());
    for (const auto& o : tx.outputs) {
      for (int b = 0; b < 8; ++b) out.push_back((o.value >> (8 * b)) & 0xff);
      tx_sign::pushVarint(out, o.scriptLen);
      out.insert(out.end(), o.script, o.script + o.scriptLen);
    }
    for (const auto& w : witnesses) {
      tx_sign::pushVarint(out, w.size());
      for (const auto& item : w) {
        tx_sign::pushVarint(out, item.size());
        out.insert(out.end(), item.begin(), item.end());
      }
    }
    for (int b = 0; b < 4; ++b) out.push_back((tx.locktime >> (8 * b)) & 0xff);
    Serial.println("[MULTISIG] threshold reached, PSBT finalized, raw transaction ready");
  } else {
    // PSBT parcial: devuelve la PSBT con las partial_sigs anadidas.
    buildPsbt(tx, extraSigs, r.partialPsbt);
    Serial.printf("[MULTISIG] PARTIALLY SIGNED %u/%u\n", r.totalSigs, r.needed);
  }
  return r;
}

}  // namespace multisig
