// Mock de SD.h: sistema de ficheros en memoria para pruebas nativas.
// API compatible con el subconjunto usado por SeedWorkstationCore.
#pragma once

#include <map>
#include <string>
#include <vector>
#include <stdint.h>
#include <string.h>

#define FILE_READ 0
#define FILE_WRITE 1
#define FILE_APPEND 2

typedef uint8_t sdcard_type_t;
const sdcard_type_t CARD_NONE = 0;
const sdcard_type_t CARD_SD = 1;
const sdcard_type_t CARD_SDHC = 2;

namespace host_sd {
inline std::map<std::string, std::vector<uint8_t>>& files() {
  static std::map<std::string, std::vector<uint8_t>> store;
  return store;
}
inline bool& present() {
  static bool p = true;
  return p;
}
inline void reset() {
  files().clear();
  present() = true;
}
inline void setPresent(bool p) { present() = p; }
inline void commit(const std::string& path, const std::vector<uint8_t>& data) {
  files()[path] = data;
}
}  // namespace host_sd

class File {
 public:
  File() : valid_(false), writeMode_(false), pos_(0) {}

  operator bool() const { return valid_; }

  size_t write(const uint8_t* p, size_t n) {
    if (!valid_ || !writeMode_) return 0;
    buf_.insert(buf_.end(), p, p + n);
    return n;
  }

  size_t read(uint8_t* p, size_t n) {
    if (!valid_ || writeMode_) return 0;
    const size_t avail = pos_ < buf_.size() ? buf_.size() - pos_ : 0;
    const size_t take = n < avail ? n : avail;
    if (take) memcpy(p, buf_.data() + pos_, take);
    pos_ += take;
    return take;
  }

  size_t size() const { return buf_.size(); }

  void flush() {}

  void close() {
    if (valid_ && writeMode_) host_sd::commit(path_, buf_);
    valid_ = false;
  }

  // Puntos de entrada usados por SD.open (ver mas abajo).
  friend class SDClass;

 private:
  bool valid_;
  bool writeMode_;
  std::string path_;
  std::vector<uint8_t> buf_;
  size_t pos_;
};

class SDClass {
 public:
  sdcard_type_t cardType() { return host_sd::present() ? CARD_SD : CARD_NONE; }

  bool exists(const char* path) {
    return host_sd::files().count(path ? path : "") != 0;
  }

  bool remove(const char* path) {
    return host_sd::files().erase(path ? path : "") != 0;
  }

  File open(const char* path, uint8_t mode) {
    File f;
    f.path_ = path ? path : "";
    if (mode == FILE_WRITE) {
      f.valid_ = true;
      f.writeMode_ = true;
      f.buf_.clear();
      f.pos_ = 0;
      return f;
    }
    // FILE_READ
    auto it = host_sd::files().find(f.path_);
    if (it == host_sd::files().end()) return f;  // no existe -> File invalido
    f.valid_ = true;
    f.writeMode_ = false;
    f.buf_ = it->second;
    f.pos_ = 0;
    return f;
  }
};
static SDClass SD;
