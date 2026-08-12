#pragma once

#include <Arduino.h>
#include <mbedtls/sha256.h>

#include "generated/bip39_english.h"

namespace bip39 {

constexpr uint16_t kInvalidWord = 0xFFFF;

inline const char* word_at(uint16_t index) {
  return index < kWordCount ? kEnglishWords[index] : "---";
}

inline uint16_t find_exact(const String& value) {
  for (uint16_t index = 0; index < kWordCount; ++index) {
    if (value.equals(word_at(index))) {
      return index;
    }
  }
  return kInvalidWord;
}

inline size_t find_matches(const String& prefix, uint16_t* matches,
                           size_t capacity) {
  if (!prefix.length()) {
    return 0;
  }

  size_t total = 0;
  for (uint16_t index = 0; index < kWordCount; ++index) {
    if (strncmp(word_at(index), prefix.c_str(), prefix.length()) == 0) {
      if (total < capacity) {
        matches[total] = index;
      }
      ++total;
    }
  }
  return total;
}

inline bool has_prefix(const String& prefix) {
  uint16_t ignored = 0;
  return find_matches(prefix, &ignored, 1) != 0;
}

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
  const uint16_t abandon = find_exact("abandon");
  const uint16_t about = find_exact("about");
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
