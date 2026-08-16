#pragma once
#include <Arduino.h>
#include <mbedtls/base64.h>
#include "bitcoin_address.hpp"
#include "ur_psbt.hpp"
#include <vector>

// Parser minimal de PSBT (BIP174) y de transacciones Bitcoin, para mostrar la
// informacion de una transaccion "como una billetera" (entradas, salidas,
// montos y comision) SIN firmar nada.
//
// El PSBT es un dato NO confiable: aqui solo se parsea/decodifica. No se valida
// ninguna firma ni se accede a claves.

namespace psbt {

constexpr size_t kMaxInputs = 128;
constexpr size_t kMaxOutputs = 256;

struct PartialSig {
  uint8_t pub[33] = {};
  uint8_t sig[74] = {};
  size_t sigLen = 0;
};

struct SignerInfo {
  uint8_t pub[33] = {};
  uint8_t fpr[4] = {};
  std::vector<uint32_t> path;
  bool hasDerivation = false;
};

struct TxOutput {
  uint64_t value = 0;                 // satoshis
  uint8_t scriptLen = 0;
  uint8_t script[80] = {};            // scriptPubKey
  String address;                     // direccion o "OP_RETURN"
  bool isChange = false;              // tiene ruta de derivacion (cambio a la wallet)
  bool hasDerivation = false;         // ruta BIP32 presente (clave 0x02)
  uint8_t derivFpr[4] = {};           // fingerprint del padre
  std::vector<uint32_t> derivPath;    // indices relativos (con bit hardened)
  uint8_t witnessScript[256] = {};    // witnessScript (clave 0x01, P2WSH)
  uint8_t witnessScriptLen = 0;
  std::vector<SignerInfo> signers;    // derivaciones por pubkey (clave 0x02)
};

struct TxInput {
  uint8_t prevTxid[32] = {};
  uint32_t prevVout = 0;
  uint32_t sequence = 0;
  uint64_t amount = 0;                // satoshis (0 si desconocido)
  bool amountKnown = false;
  String address;                     // direccion del UTXO previo
  bool hasDerivation = false;         // ruta BIP32 presente (clave 0x06)
  uint8_t derivFpr[4] = {};           // fingerprint del padre
  std::vector<uint32_t> derivPath;    // indices relativos (con bit hardened)
  uint8_t utxoScript[80] = {};        // scriptPubKey del UTXO gastado (witness/non-witness)
  uint8_t utxoScriptLen = 0;
  uint8_t redeemScript[34] = {};      // redeemScript (clave 0x04, P2SH-P2WPKH)
  uint8_t redeemScriptLen = 0;
  uint8_t witnessScript[256] = {};    // redeem/witness script (clave 0x05, P2WSH)
  uint8_t witnessScriptLen = 0;
  std::vector<PartialSig> partialSigs;  // firmas parciales ya presentes (clave 0x02)
  std::vector<SignerInfo> signers;      // derivaciones por pubkey (clave 0x06)
};

struct ParsedTx {
  uint32_t version = 0;
  std::vector<TxInput> inputs;
  std::vector<TxOutput> outputs;
  uint32_t locktime = 0;
  uint64_t totalOut = 0;
  uint64_t totalIn = 0;
  uint64_t totalPay = 0;              // salidas sin ruta de derivacion (pago)
  uint64_t totalChange = 0;           // salidas con ruta de derivacion (cambio)
  bool hasChangeInfo = false;         // el PSBT marca al menos una salida como cambio
  bool inputsComplete = false;        // todas las entradas tienen monto
  int64_t fee = 0;                    // totalIn - totalOut (si inputsComplete)
};

inline int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline String scriptToAddress(const uint8_t* s, size_t len) {
  if (len == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 &&
      s[23] == 0x88 && s[24] == 0xac)
    return bitcoin_address::base58_address(0, s + 3);
  if (len == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87)
    return bitcoin_address::base58_address(5, s + 2);
  if (len == 22 && s[0] == 0x00 && s[1] == 0x14)
    return bitcoin_address::segwit_address(0, s + 2, 20);
  if (len == 34 && s[0] == 0x00 && s[1] == 0x20)
    return bitcoin_address::segwit_address(0, s + 2, 32);
  if (len == 34 && s[0] == 0x51 && s[1] == 0x20)
    return bitcoin_address::segwit_address(1, s + 2, 32);
  if (len >= 1 && s[0] == 0x6a) return "OP_RETURN";
  return "";
}

// Devuelve bytes consumidos (0 si error o datos insuficientes).
inline size_t readVarint(const uint8_t* p, size_t avail, uint64_t& out) {
  if (avail < 1) return 0;
  const uint8_t b = p[0];
  if (b < 0xfd) { out = b; return 1; }
  if (b == 0xfd) {
    if (avail < 3) return 0;
    out = static_cast<uint64_t>(p[1]) | (static_cast<uint64_t>(p[2]) << 8);
    return 3;
  }
  if (b == 0xfe) {
    if (avail < 5) return 0;
    out = static_cast<uint64_t>(p[1]) | (static_cast<uint64_t>(p[2]) << 8) |
          (static_cast<uint64_t>(p[3]) << 16) | (static_cast<uint64_t>(p[4]) << 24);
    return 5;
  }
  if (avail < 9) return 0;
  out = static_cast<uint64_t>(p[1]) | (static_cast<uint64_t>(p[2]) << 8) |
        (static_cast<uint64_t>(p[3]) << 16) | (static_cast<uint64_t>(p[4]) << 24) |
        (static_cast<uint64_t>(p[5]) << 32) | (static_cast<uint64_t>(p[6]) << 40) |
        (static_cast<uint64_t>(p[7]) << 48) | (static_cast<uint64_t>(p[8]) << 56);
  return 9;
}

// Parsea una transaccion cruda; deja en *consumed* los bytes leidos.
inline bool parseTx(const uint8_t* p, size_t len, ParsedTx& tx, size_t& consumed) {
  size_t i = 0;
  if (len < 4) return false;
  tx.version = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  i += 4;

  uint64_t vinCount = 0;
  size_t n = readVarint(p + i, len - i, vinCount);
  if (!n || vinCount > kMaxInputs) return false;
  i += n;
  tx.inputs.clear();
  tx.inputs.reserve(static_cast<size_t>(vinCount));
  for (uint64_t k = 0; k < vinCount; ++k) {
    TxInput in;
    if (len - i < 36) return false;
    memcpy(in.prevTxid, p + i, 32); i += 32;
    in.prevVout = static_cast<uint32_t>(p[i]) | (static_cast<uint32_t>(p[i + 1]) << 8) |
                  (static_cast<uint32_t>(p[i + 2]) << 16) | (static_cast<uint32_t>(p[i + 3]) << 24);
    i += 4;
    uint64_t scriptLen = 0;
    n = readVarint(p + i, len - i, scriptLen);
    if (!n) return false;
    i += n;
    if (len - i < scriptLen) return false;
    i += scriptLen;              // scriptSig
    if (len - i < 4) return false;
    in.sequence = static_cast<uint32_t>(p[i]) | (static_cast<uint32_t>(p[i + 1]) << 8) |
                  (static_cast<uint32_t>(p[i + 2]) << 16) | (static_cast<uint32_t>(p[i + 3]) << 24);
    i += 4;                      // sequence
    tx.inputs.push_back(in);
  }

  uint64_t voutCount = 0;
  n = readVarint(p + i, len - i, voutCount);
  if (!n || voutCount > kMaxOutputs) return false;
  i += n;
  tx.outputs.clear();
  tx.outputs.reserve(static_cast<size_t>(voutCount));
  tx.totalOut = 0;
  for (uint64_t k = 0; k < voutCount; ++k) {
    TxOutput out;
    if (len - i < 8) return false;
    out.value = 0;
    for (int b = 0; b < 8; ++b) out.value |= static_cast<uint64_t>(p[i + b]) << (8 * b);
    i += 8;
    uint64_t scriptLen = 0;
    n = readVarint(p + i, len - i, scriptLen);
    if (!n) return false;
    i += n;
    if (len - i < scriptLen) return false;
    if (scriptLen <= sizeof(out.script)) {
      memcpy(out.script, p + i, static_cast<size_t>(scriptLen));
      out.scriptLen = static_cast<uint8_t>(scriptLen);
    }
    i += scriptLen;
    out.address = scriptToAddress(out.script, out.scriptLen);
    tx.outputs.push_back(out);
    tx.totalOut += out.value;
  }

  if (len - i < 4) return false;
  tx.locktime = static_cast<uint32_t>(p[i]) | (static_cast<uint32_t>(p[i + 1]) << 8) |
                (static_cast<uint32_t>(p[i + 2]) << 16) | (static_cast<uint32_t>(p[i + 3]) << 24);
  i += 4;
  consumed = i;
  return true;
}

inline bool isPsbtMagic(const uint8_t* p, size_t n) {
  return n >= 5 && p[0] == 0x70 && p[1] == 0x73 && p[2] == 0x62 && p[3] == 0x74 && p[4] == 0xff;
}

inline bool parsePsbt(const std::vector<uint8_t>& data, ParsedTx& tx) {
  if (!isPsbtMagic(data.data(), data.size())) return false;
  size_t i = 5;
  const uint8_t* rawTx = nullptr;
  size_t rawTxLen = 0;
  uint64_t keyLen = 0, valLen = 0;
  size_t n;

  // Mapa global: buscar la transaccion sin firmar (key 0x00).
  while (i < data.size()) {
    n = readVarint(data.data() + i, data.size() - i, keyLen);
    if (!n) return false;
    i += n;
    if (keyLen == 0) break;                 // fin del mapa
    if (data.size() - i < keyLen) return false;
    const uint8_t* key = data.data() + i; i += keyLen;
    n = readVarint(data.data() + i, data.size() - i, valLen);
    if (!n) return false;
    i += n;
    if (data.size() - i < valLen) return false;
    const uint8_t* val = data.data() + i; i += valLen;
    if (keyLen >= 1 && key[0] == 0x00) { rawTx = val; rawTxLen = valLen; }
  }
  if (!rawTx) return false;
  size_t consumed = 0;
  if (!parseTx(rawTx, rawTxLen, tx, consumed)) return false;

  // Mapas de entrada: buscar witness UTXO (0x01) o non-witness UTXO (0x00).
  for (size_t inIdx = 0; inIdx < tx.inputs.size(); ++inIdx) {
    while (i < data.size()) {
      n = readVarint(data.data() + i, data.size() - i, keyLen);
      if (!n) return false;
      i += n;
      if (keyLen == 0) break;               // fin del mapa de entrada
      if (data.size() - i < keyLen) return false;
      const uint8_t* key = data.data() + i; i += keyLen;
      n = readVarint(data.data() + i, data.size() - i, valLen);
      if (!n) return false;
      i += n;
      if (data.size() - i < valLen) return false;
      const uint8_t* val = data.data() + i; i += valLen;

      if (keyLen >= 1 && key[0] == 0x01 && valLen >= 8) {
        uint64_t amount = 0;
        for (int b = 0; b < 8; ++b) amount |= static_cast<uint64_t>(val[b]) << (8 * b);
        tx.inputs[inIdx].amount = amount;
        tx.inputs[inIdx].amountKnown = true;
        uint64_t spkLen = 0;
        size_t sn = readVarint(val + 8, valLen - 8, spkLen);
        if (sn && 8 + sn + spkLen <= valLen) {
          const uint8_t* spk = val + 8 + sn;
          tx.inputs[inIdx].address = scriptToAddress(spk, static_cast<size_t>(spkLen));
          if (spkLen <= sizeof(tx.inputs[inIdx].utxoScript)) {
            memcpy(tx.inputs[inIdx].utxoScript, spk, static_cast<size_t>(spkLen));
            tx.inputs[inIdx].utxoScriptLen = static_cast<uint8_t>(spkLen);
          }
        }
      } else if (keyLen >= 1 && key[0] == 0x00 && !tx.inputs[inIdx].amountKnown) {
        ParsedTx prev;
        size_t pc = 0;
        if (parseTx(val, static_cast<size_t>(valLen), prev, pc) &&
            tx.inputs[inIdx].prevVout < prev.outputs.size()) {
          const TxOutput& o = prev.outputs[tx.inputs[inIdx].prevVout];
          tx.inputs[inIdx].amount = o.value;
          tx.inputs[inIdx].amountKnown = true;
          tx.inputs[inIdx].address = o.address;
          if (o.scriptLen <= sizeof(tx.inputs[inIdx].utxoScript)) {
            memcpy(tx.inputs[inIdx].utxoScript, o.script, o.scriptLen);
            tx.inputs[inIdx].utxoScriptLen = o.scriptLen;
          }
        }
      } else if (keyLen >= 1 && key[0] == 0x06 && valLen >= 4) {
        // BIP32 derivation: key = {0x06}|{pubkey(33)}, value = {fpr(4)}|{path}.
        uint8_t fpr[4]; memcpy(fpr, val, 4);
        std::vector<uint32_t> path;
        size_t off = 4;
        while (off + 4 <= valLen) {
          uint32_t idx = static_cast<uint32_t>(val[off]) |
                         (static_cast<uint32_t>(val[off + 1]) << 8) |
                         (static_cast<uint32_t>(val[off + 2]) << 16) |
                         (static_cast<uint32_t>(val[off + 3]) << 24);
          path.push_back(idx);
          off += 4;
        }
        if (!tx.inputs[inIdx].hasDerivation) {
          memcpy(tx.inputs[inIdx].derivFpr, fpr, 4);
          tx.inputs[inIdx].derivPath = path;
          tx.inputs[inIdx].hasDerivation = true;
        }
        if (keyLen >= 34) {
          SignerInfo si;
          memcpy(si.pub, key + 1, 33);
          memcpy(si.fpr, fpr, 4);
          si.path = path;
          si.hasDerivation = true;
          tx.inputs[inIdx].signers.push_back(si);
        }
      } else if (keyLen >= 1 && key[0] == 0x04 && valLen <= sizeof(tx.inputs[inIdx].redeemScript)) {
        // redeemScript (P2SH-P2WPKH / P2SH).
        memcpy(tx.inputs[inIdx].redeemScript, val, static_cast<size_t>(valLen));
        tx.inputs[inIdx].redeemScriptLen = static_cast<uint8_t>(valLen);
      } else if (keyLen >= 1 && key[0] == 0x05 && valLen <= sizeof(tx.inputs[inIdx].witnessScript)) {
        // witnessScript (P2WSH multisig).
        memcpy(tx.inputs[inIdx].witnessScript, val, static_cast<size_t>(valLen));
        tx.inputs[inIdx].witnessScriptLen = static_cast<uint8_t>(valLen);
      } else if (keyLen >= 34 && key[0] == 0x02) {
        // partial_sig: key = {0x02}|{pubkey(33)}, value = {signature}.
        PartialSig ps;
        memcpy(ps.pub, key + 1, 33);
        ps.sigLen = valLen;
        if (ps.sigLen <= sizeof(ps.sig)) memcpy(ps.sig, val, ps.sigLen);
        tx.inputs[inIdx].partialSigs.push_back(ps);
      }
    }
  }

  // Mapas de salida: detectar el cambio (ruta de derivacion BIP32, clave 0x02).
  for (size_t outIdx = 0; outIdx < tx.outputs.size(); ++outIdx) {
    while (i < data.size()) {
      n = readVarint(data.data() + i, data.size() - i, keyLen);
      if (!n) return false;
      i += n;
      if (keyLen == 0) break;               // fin del mapa de salida
      if (data.size() - i < keyLen) return false;
      const uint8_t* key = data.data() + i; i += keyLen;
      n = readVarint(data.data() + i, data.size() - i, valLen);
      if (!n) return false;
      i += n;
      if (data.size() - i < valLen) return false;
      const uint8_t* val = data.data() + i; i += valLen;
      if (keyLen >= 1 && key[0] == 0x01 && valLen <= sizeof(tx.outputs[outIdx].witnessScript)) {
        // witnessScript / redeemScript del output (P2WSH).
        memcpy(tx.outputs[outIdx].witnessScript, val, static_cast<size_t>(valLen));
        tx.outputs[outIdx].witnessScriptLen = static_cast<uint8_t>(valLen);
      } else if (keyLen >= 1 && key[0] == 0x02 && valLen >= 4) {
        // BIP32 derivation: key = {0x02}|{pubkey(33)}, value = {fpr(4)}|{path}.
        uint8_t fpr[4]; memcpy(fpr, val, 4);
        tx.outputs[outIdx].isChange = true;
        tx.hasChangeInfo = true;
        tx.outputs[outIdx].hasDerivation = true;
        memcpy(tx.outputs[outIdx].derivFpr, fpr, 4);
        tx.outputs[outIdx].derivPath.clear();
        size_t off = 4;
        while (off + 4 <= valLen) {
          uint32_t idx = static_cast<uint32_t>(val[off]) |
                         (static_cast<uint32_t>(val[off + 1]) << 8) |
                         (static_cast<uint32_t>(val[off + 2]) << 16) |
                         (static_cast<uint32_t>(val[off + 3]) << 24);
          tx.outputs[outIdx].derivPath.push_back(idx);
          off += 4;
        }
        if (keyLen >= 34) {
          SignerInfo si;
          memcpy(si.pub, key + 1, 33);
          memcpy(si.fpr, fpr, 4);
          si.path = tx.outputs[outIdx].derivPath;
          si.hasDerivation = true;
          tx.outputs[outIdx].signers.push_back(si);
        }
      }
    }
  }

  // Totales y comision.
  tx.totalIn = 0;
  tx.inputsComplete = true;
  for (const auto& in : tx.inputs) {
    if (!in.amountKnown) { tx.inputsComplete = false; break; }
    tx.totalIn += in.amount;
  }
  tx.totalPay = 0;
  tx.totalChange = 0;
  for (const auto& o : tx.outputs) {
    if (o.isChange) tx.totalChange += o.value;
    else tx.totalPay += o.value;
  }
  tx.fee = tx.inputsComplete ? static_cast<int64_t>(tx.totalIn) - static_cast<int64_t>(tx.totalOut)
                             : 0;
  return true;
}

// Detecta y parsea un PSBT en binario, base64, hex o UR (crypto-psbt).
inline bool tryParsePsbt(const std::vector<uint8_t>& data, ParsedTx& tx) {
  if (isPsbtMagic(data.data(), data.size())) return parsePsbt(data, tx);

  // UR crypto-psbt (bytewords) — p.ej. "ur:crypto-psbt/HKAD...".
  {
    String ur;
    ur.reserve(data.size());
    for (uint8_t c : data) ur += static_cast<char>(c);
    std::vector<uint8_t> psbt;
    if (ur::decodeCryptoPsbt(ur, psbt)) return parsePsbt(psbt, tx);
  }

  // Base64 (tolerando espacios y saltos de linea).
  if (data.size() < 1024) {
    std::vector<uint8_t> clean;
    clean.reserve(data.size());
    for (uint8_t c : data)
      if (c != ' ' && c != '\n' && c != '\r' && c != '\t') clean.push_back(c);
    std::vector<uint8_t> buf(clean.size());
    size_t olen = 0;
    if (!clean.empty() &&
        mbedtls_base64_decode(buf.data(), buf.size(), &olen, clean.data(), clean.size()) == 0) {
      if (isPsbtMagic(buf.data(), olen)) {
        std::vector<uint8_t> v(buf.begin(), buf.begin() + olen);
        return parsePsbt(v, tx);
      }
    }
  }

  // Hex.
  if (data.size() > 10 && data.size() % 2 == 0 && data.size() < 4096) {
    std::vector<uint8_t> buf(data.size() / 2);
    bool ok = true;
    for (size_t i = 0; i < buf.size(); ++i) {
      const int hi = hexVal(static_cast<char>(data[i * 2]));
      const int lo = hexVal(static_cast<char>(data[i * 2 + 1]));
      if (hi < 0 || lo < 0) { ok = false; break; }
      buf[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    if (ok && isPsbtMagic(buf.data(), buf.size())) return parsePsbt(buf, tx);
  }
  return false;
}

// Formatea satoshis a BTC legible (sin ceros finales).
inline String formatSats(uint64_t sats) {
  const uint64_t btc = sats / 100000000ULL;
  const uint32_t frac = static_cast<uint32_t>(sats % 100000000ULL);
  char buf[40];
  snprintf(buf, sizeof(buf), "%llu.%08lu", static_cast<unsigned long long>(btc),
           static_cast<unsigned long>(frac));
  String s = buf;
  while (s.length() > 1 && s.charAt(s.length() - 1) == '0') s.remove(s.length() - 1);
  if (s.charAt(s.length() - 1) == '.') s.remove(s.length() - 1);
  return s;
}

// Vector de prueba: PSBT minimal (1 entrada witness UTXO de 1000 sats, 1 salida
// P2PKH de 1000 sats). Verifica el parseo completo.
inline bool self_test() {
  static const char hex[] =
      "70736274ff"
      "010055020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a914111111111111111111111111111111111111111188ac00000000"
      "00010122e8030000000000001976a914111111111111111111111111111111111111111188ac0000";
  std::vector<uint8_t> data(strlen(hex) / 2);
  for (size_t i = 0; i < data.size(); ++i) {
    const int hi = hexVal(hex[i * 2]);
    const int lo = hexVal(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    data[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  ParsedTx tx;
  if (!parsePsbt(data, tx)) return false;
  return tx.version == 2 && tx.inputs.size() == 1 && tx.outputs.size() == 1 &&
         tx.totalOut == 1000 && tx.inputsComplete && tx.totalIn == 1000 &&
         tx.fee == 0 && tx.totalPay == 1000 && tx.totalChange == 0 &&
         tx.outputs[0].address.startsWith("1");
}

}  // namespace psbt
