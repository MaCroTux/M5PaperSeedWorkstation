#pragma once
#include <Arduino.h>
#include <vector>

// BBQr — Better Bitcoin QR (Coinkite).
//
// Cada frame es: "B$" + encoding + type + total(2 base36) + index(2 base36) +
// payload en HEX MAYUSCULAS. Cabecera de 8 caracteres.
//
//   B$   → identificacion BBQr
//   H    → payload codificado en HEX
//   P/T  → P = PSBT, T = transaccion Bitcoin (wire)
//   total → numero total de partes (2 digitos base36, 00..ZZ)
//   index → indice de esta parte (2 digitos base36, empieza en 00)
//
// Ejemplo (3 partes): B$HP0300... / B$HP0301... / B$HP0302...

namespace bbqr {

constexpr char kEncodingHex = 'H';
constexpr char kTypePsbt = 'P';
constexpr char kTypeTx = 'T';
constexpr size_t kPreferredBlockSize = 800;

struct Layout {
  size_t totalParts = 1;
  size_t blockSize = 0;
};

// Dos digitos base36 (0-9, A-Z). 0 -> "00", 35 -> "0Z", 36 -> "10", 1295 -> "ZZ".
inline String base36TwoDigits(uint16_t value) {
  static const char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  String r;
  r += digits[(value / 36) % 36];
  r += digits[value % 36];
  return r;
}

inline String bytesToUpperHex(const uint8_t* data, size_t len) {
  static const char hex[] = "0123456789ABCDEF";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out += hex[data[i] >> 4];
    out += hex[data[i] & 0xF];
  }
  return out;
}

// Division balanceada: totalParts = ceil(size/preferred); blockSize = ceil(size/totalParts).
inline Layout calculateLayout(size_t dataSize, size_t preferred) {
  Layout l;
  l.totalParts = (dataSize + preferred - 1) / preferred;
  if (l.totalParts == 0) l.totalParts = 1;
  l.blockSize = (dataSize + l.totalParts - 1) / l.totalParts;
  return l;
}

// Construye el frame completo para una parte. index es 0-based.
inline String makeFrame(const uint8_t* data, size_t dataSize, char type,
                        uint16_t totalParts, uint16_t index, size_t blockSize) {
  String frame;
  frame.reserve(8 + blockSize * 2);
  frame += "B$";
  frame += kEncodingHex;
  frame += type;
  frame += base36TwoDigits(totalParts);
  frame += base36TwoDigits(index);
  const size_t start = static_cast<size_t>(index) * blockSize;
  size_t len = blockSize;
  if (start + len > dataSize) len = dataSize - start;
  frame += bytesToUpperHex(data + start, len);
  return frame;
}

}  // namespace bbqr
