// Mock de Preferences.h: almacen clave/valor en memoria para pruebas nativas.
// API compatible con el subconjunto usado por ble_key.hpp / vault_key.hpp.
#pragma once

#include <map>
#include <string>
#include <vector>
#include <stdint.h>
#include <stddef.h>

namespace host_prefs {
inline std::map<std::string, std::map<std::string, std::vector<uint8_t>>>& store() {
  static std::map<std::string, std::map<std::string, std::vector<uint8_t>>> s;
  return s;
}
inline void reset() { store().clear(); }
}  // namespace host_prefs

class Preferences {
 public:
  bool begin(const char* ns, bool /*readOnly*/) {
    ns_ = ns ? ns : "";
    return true;
  }
  void end() {}

  size_t getBytesLength(const char* key) const {
    auto ns = host_prefs::store().find(ns_);
    if (ns == host_prefs::store().end()) return 0;
    auto k = ns->second.find(key);
    return k == ns->second.end() ? 0 : k->second.size();
  }

  size_t getBytes(const char* key, uint8_t* out, size_t len) const {
    auto ns = host_prefs::store().find(ns_);
    if (ns == host_prefs::store().end()) return 0;
    auto k = ns->second.find(key);
    if (k == ns->second.end()) return 0;
    const size_t n = k->second.size() < len ? k->second.size() : len;
    if (n) memcpy(out, k->second.data(), n);
    return n;
  }

  size_t putBytes(const char* key, const uint8_t* in, size_t len) {
    auto& v = host_prefs::store()[ns_][key];
    v.assign(in, in + len);
    return len;
  }

  bool remove(const char* key) {
    auto ns = host_prefs::store().find(ns_);
    if (ns == host_prefs::store().end()) return false;
    return ns->second.erase(key) != 0;
  }

 private:
  std::string ns_;
};
