// Shim de Arduino.h para pruebas nativas (host).
// Proporciona lo minimo que usa SeedWorkstationCore: String, PROGMEM,
// esp_fill_random (determinista) y un Serial no-op.
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <string>
#include <cstdio>

// En host no hay memoria flash: PROGMEM y los helpers pgm_* son no-ops.
#define PROGMEM
#define pgm_read_byte(addr) (*(const uint8_t*)(addr))
#define pgm_read_word(addr) (*(const uint16_t*)(addr))
#define pgm_read_ptr(addr) (*(void* const*)(addr))

// ---------------------------------------------------------------------------
// RNG determinista (reemplaza al RNG de hardware del ESP32).
// ---------------------------------------------------------------------------
namespace host {
inline uint32_t& rngState() {
  static uint32_t state = 0x12345678u;
  return state;
}
inline void seedRandom(uint32_t seed) { rngState() = seed; }
inline uint32_t nextRandom() {
  // xorshift32
  uint32_t x = rngState();
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  rngState() = x;
  return x;
}
}  // namespace host

inline uint32_t esp_random() { return host::nextRandom(); }

inline void esp_fill_random(void* buf, size_t len) {
  uint8_t* p = static_cast<uint8_t*>(buf);
  for (size_t i = 0; i < len; ++i) {
    p[i] = static_cast<uint8_t>(host::nextRandom() & 0xff);
  }
}

// ---------------------------------------------------------------------------
// Serial no-op (la logica de core usa Serial solo para depuracion).
// ---------------------------------------------------------------------------
struct SerialClass {
  template <typename... Args>
  int printf(const char*, Args&&...) {
    return 0;
  }
  template <typename... Args>
  void print(Args&&...) {}
  template <typename... Args>
  void println(Args&&...) {}
  void begin(unsigned long) {}
  void flush() {}
  void write(uint8_t) {}
  void end() {}
};
static SerialClass Serial;

// ---------------------------------------------------------------------------
// String minimal compatible con el API de Arduino usado en el core.
// ---------------------------------------------------------------------------
class String {
 public:
  String() {}
  String(const char* s) : s_(s ? s : "") {}
  String(const char* s, size_t n) : s_(s ? std::string(s, n) : std::string()) {}
  String(const String& o) = default;
  String(String&& o) = default;
  String& operator=(const String& o) = default;
  String& operator=(String&& o) = default;
  String& operator=(const char* s) {
    s_ = s ? s : "";
    return *this;
  }

  const char* c_str() const { return s_.c_str(); }
  size_t length() const { return s_.size(); }
  void reserve(size_t n) { s_.reserve(n); }

  char charAt(size_t i) const { return s_[i]; }
  char operator[](size_t i) const { return s_[i]; }

  String& operator+=(const char* s) { s_ += (s ? s : ""); return *this; }
  String& operator+=(char c) { s_ += c; return *this; }
  String& operator+=(const String& o) { s_ += o.s_; return *this; }

  String substring(size_t from) const {
    if (from >= s_.size()) return String();
    return String(s_.substr(from).c_str());
  }

  int indexOf(const char* needle) const {
    if (!needle) return -1;
    const size_t pos = s_.find(needle);
    return pos == std::string::npos ? -1 : static_cast<int>(pos);
  }

  void toLowerCase() {
    for (auto& c : s_)
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }

  bool startsWith(const char* prefix) const {
    if (!prefix) return false;
    const size_t n = strlen(prefix);
    return s_.size() >= n && s_.compare(0, n, prefix) == 0;
  }

  bool equals(const char* s) const { return s_.compare(s ? s : "") == 0; }
  bool equals(const String& o) const { return s_ == o.s_; }

  void remove(size_t index, size_t count = 1) {
    if (index < s_.size()) s_.erase(index, count);
  }

 private:
  std::string s_;
};

inline bool operator==(const String& a, const String& b) { return a.equals(b); }
inline bool operator==(const String& a, const char* b) { return a.equals(b); }
inline bool operator==(const char* a, const String& b) { return b.equals(a); }
inline bool operator!=(const String& a, const String& b) { return !a.equals(b); }
inline bool operator!=(const String& a, const char* b) { return !a.equals(b); }
inline bool operator!=(const char* a, const String& b) { return !b.equals(a); }

// ---------------------------------------------------------------------------
// Utiles adicionales que suele proveer Arduino.h
// ---------------------------------------------------------------------------
typedef uint8_t byte;
typedef bool boolean;
