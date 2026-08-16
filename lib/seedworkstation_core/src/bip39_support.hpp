#pragma once

#include <Arduino.h>
#include <mbedtls/sha256.h>

#include "generated/bip39_english.h"
#include "generated/bip39_spanish.h"

namespace bip39 {

constexpr uint16_t kInvalidWord = 0xFFFF;

enum class Wordlist : uint8_t { English = 0, Spanish = 1 };

// Wordlist activa. Definida en bip39_wordlist.cpp (unica definicion).
extern Wordlist g_wordlist;

inline void set_wordlist(Wordlist lang) { g_wordlist = lang; }
inline Wordlist wordlist_lang() { return g_wordlist; }

inline const char* const* wordlist(Wordlist lang) {
  return lang == Wordlist::Spanish ? kSpanishWords : kEnglishWords;
}

// ---------------------------------------------------------------------------
// Plegado de acentos (solo espanol). Convierte una secuencia UTF-8 (NFC) a su
// equivalente ASCII para permitir escribir "abaco" y que case con "abaco".
// ---------------------------------------------------------------------------
inline char fold_utf8(const char*& p, const char* end) {
  const unsigned char c = static_cast<unsigned char>(*p);
  if (c < 0x80) { ++p; return static_cast<char>(c); }
  if (c == 0xC3 && p + 1 < end) {
    const unsigned char c2 = static_cast<unsigned char>(p[1]);
    p += 2;
    switch (c2) {
      case 0xA1: case 0x81: return 'a';  // á Á
      case 0xA9: case 0x89: return 'e';  // é É
      case 0xAD: case 0x8D: return 'i';  // í Í
      case 0xB3: case 0x93: return 'o';  // ó Ó
      case 0xBA: case 0x9A: case 0xBC: case 0x9C: return 'u';  // ú ú ü Ü
      case 0xB1: case 0x91: return 'n';  // ñ Ñ
      default: return '?';
    }
  }
  ++p;
  return '?';
}

inline bool folded_equal(const char* a, const char* b) {
  const char* ae = a + strlen(a);
  const char* be = b + strlen(b);
  while (a < ae && b < be) {
    if (fold_utf8(a, ae) != fold_utf8(b, be)) return false;
  }
  return a == ae && b == be;
}

inline bool folded_prefix(const char* prefix, const char* word) {
  const char* pe = prefix + strlen(prefix);
  const char* we = word + strlen(word);
  const char* p = prefix;
  const char* w = word;
  while (p < pe && w < we) {
    if (fold_utf8(p, pe) != fold_utf8(w, we)) return false;
  }
  return p == pe;
}

inline const char* word_at(uint16_t index, Wordlist lang) {
  return index < kWordCount ? wordlist(lang)[index] : "---";
}
inline const char* word_at(uint16_t index) { return word_at(index, g_wordlist); }

inline uint16_t find_exact(const String& value, Wordlist lang) {
  const char* const* wl = wordlist(lang);
  for (uint16_t index = 0; index < kWordCount; ++index) {
    if (folded_equal(value.c_str(), wl[index])) return index;
  }
  return kInvalidWord;
}
inline uint16_t find_exact(const String& value) { return find_exact(value, g_wordlist); }

inline size_t find_matches(const String& prefix, uint16_t* matches,
                           size_t capacity, Wordlist lang) {
  if (!prefix.length()) return 0;
  const char* const* wl = wordlist(lang);
  size_t total = 0;
  for (uint16_t index = 0; index < kWordCount; ++index) {
    if (folded_prefix(prefix.c_str(), wl[index])) {
      if (total < capacity) matches[total] = index;
      ++total;
    }
  }
  return total;
}
inline size_t find_matches(const String& prefix, uint16_t* matches,
                           size_t capacity) {
  return find_matches(prefix, matches, capacity, g_wordlist);
}

inline bool has_prefix(const String& prefix, Wordlist lang) {
  uint16_t ignored = 0;
  return find_matches(prefix, &ignored, 1, lang) != 0;
}
inline bool has_prefix(const String& prefix) { return has_prefix(prefix, g_wordlist); }

inline bool checksum_valid(const uint16_t* indices, size_t word_count) {
  if (word_count != 12 && word_count != 24) {
    return false;
  }

  uint8_t packed[33] = {};
  size_t bit_position = 0;
  for (size_t word = 0; word < word_count; ++word) {
    if (indices[word] >= kWordCount) {
      return false;
    }
    for (int bit = 10; bit >= 0; --bit, ++bit_position) {
      if (indices[word] & (1U << bit)) {
        packed[bit_position / 8] |= 1U << (7 - (bit_position % 8));
      }
    }
  }

  const size_t entropy_bytes = word_count == 12 ? 16 : 32;
  const uint8_t checksum_bits = word_count == 12 ? 4 : 8;
  uint8_t digest[32] = {};
  if (mbedtls_sha256_ret(packed, entropy_bytes, digest, 0) != 0) {
    return false;
  }

  const uint8_t supplied = packed[entropy_bytes] >> (8 - checksum_bits);
  const uint8_t expected = digest[0] >> (8 - checksum_bits);
  return supplied == expected;
}

// Extrae la entropia (128/256 bits) de unos indices BIP39 (inversa de from_entropy).
inline bool to_entropy(const uint16_t* indices, size_t word_count, uint8_t* out) {
  if (word_count != 12 && word_count != 24) return false;
  const size_t entropy_bytes = word_count == 12 ? 16 : 32;
  uint8_t packed[33] = {};
  size_t bit_position = 0;
  for (size_t word = 0; word < word_count; ++word) {
    for (int bit = 10; bit >= 0; --bit, ++bit_position) {
      if (indices[word] & (1U << bit)) {
        packed[bit_position / 8] |= 1U << (7 - (bit_position % 8));
      }
    }
  }
  memcpy(out, packed, entropy_bytes);
  return true;
}

inline bool from_entropy(const uint8_t* entropy, size_t entropy_bytes,
                         uint16_t* indices, size_t word_count) {
  if ((entropy_bytes != 16 || word_count != 12) &&
      (entropy_bytes != 32 || word_count != 24)) {
    return false;
  }
  uint8_t digest[32] = {};
  if (mbedtls_sha256_ret(entropy, entropy_bytes, digest, 0) != 0) {
    return false;
  }
  const size_t checksum_bits = entropy_bytes * 8 / 32;
  const size_t total_bits = entropy_bytes * 8 + checksum_bits;
  for (size_t word = 0; word < word_count; ++word) {
    uint16_t value = 0;
    for (size_t bit = 0; bit < 11; ++bit) {
      const size_t position = word * 11 + bit;
      bool set = false;
      if (position < entropy_bytes * 8) {
        set = entropy[position / 8] & (1U << (7 - position % 8));
      } else {
        const size_t checksum_position = position - entropy_bytes * 8;
        set = digest[checksum_position / 8] &
              (1U << (7 - checksum_position % 8));
      }
      value = static_cast<uint16_t>((value << 1) | (set ? 1 : 0));
    }
    indices[word] = value;
  }
  return total_bits == word_count * 11 && checksum_valid(indices, word_count);
}

inline bool self_test() {
  uint16_t vector[12];
  const uint16_t abandon = find_exact("abandon", Wordlist::English);
  const uint16_t about = find_exact("about", Wordlist::English);
  if (abandon == kInvalidWord || about == kInvalidWord) {
    return false;
  }
  for (size_t i = 0; i < 11; ++i) {
    vector[i] = abandon;
  }
  vector[11] = about;
  return checksum_valid(vector, 12);
}

}  // namespace bip39
