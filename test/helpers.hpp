// Helpers comunes para los tests host.
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

namespace testutil {

inline int hexNib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline std::vector<uint8_t> hex(const char* s) {
  std::vector<uint8_t> out;
  const size_t n = strlen(s);
  out.resize(n / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>((hexNib(s[2 * i]) << 4) | hexNib(s[2 * i + 1]));
  }
  return out;
}

inline bool eq(const uint8_t* a, const uint8_t* b, size_t n) {
  return memcmp(a, b, n) == 0;
}

}  // namespace testutil
