#pragma once
#include <Arduino.h>
#include <SD.h>
#include <string.h>

// Configuracion persistente del dispositivo, guardada en la SD.
// Formato del fichero (11 bytes):
//   [0..3]  magia "M5CF"
//   [4]     version = 1
//   [5]     idioma (0 = ingles, 1 = espanol)
//   [6]     derivacion por defecto (0..3 = BIP44/49/84/86)
//   [7..10] tiempo de bloqueo en milisegundos (uint32, little-endian; 0 = nunca)

namespace device_settings {

constexpr char kPath[] = "/m5settings.cfg";

// Opciones de tiempo de bloqueo (ms). 0 = nunca.
constexpr uint32_t kTimeoutNone = 0;
constexpr uint32_t kTimeout1m = 60000;
constexpr uint32_t kTimeout3m = 180000;
constexpr uint32_t kTimeout5m = 300000;
constexpr uint32_t kTimeout10m = 600000;

constexpr uint32_t kTimeoutOptions[] = {
    kTimeout1m, kTimeout3m, kTimeout5m, kTimeout10m, kTimeoutNone};
constexpr uint8_t kTimeoutOptionCount = sizeof(kTimeoutOptions) / sizeof(kTimeoutOptions[0]);

struct Settings {
  uint8_t language;        // 0 = EN, 1 = ES
  uint8_t defaultProfile;  // 0..3
  uint32_t lockTimeoutMs;  // 0 = nunca
};

inline Settings defaults() {
  Settings s;
  s.language = 0;
  s.defaultProfile = 2;  // BIP84
  s.lockTimeoutMs = kTimeout3m;
  return s;
}

inline bool valid(const Settings& s) {
  if (s.language > 1 || s.defaultProfile > 3) return false;
  if (s.lockTimeoutMs == kTimeoutNone) return true;
  for (uint8_t i = 0; i < kTimeoutOptionCount; ++i)
    if (s.lockTimeoutMs == kTimeoutOptions[i]) return true;
  return false;
}

inline bool save(const Settings& s) {
  if (SD.cardType() == CARD_NONE) return false;
  File f = SD.open(kPath, FILE_WRITE);
  if (!f) return false;
  uint8_t buf[11];
  memcpy(buf, "M5CF", 4);
  buf[4] = 1;
  buf[5] = s.language;
  buf[6] = s.defaultProfile;
  buf[7] = s.lockTimeoutMs & 0xFF;
  buf[8] = (s.lockTimeoutMs >> 8) & 0xFF;
  buf[9] = (s.lockTimeoutMs >> 16) & 0xFF;
  buf[10] = (s.lockTimeoutMs >> 24) & 0xFF;
  const bool ok = f.write(buf, sizeof(buf)) == sizeof(buf);
  f.flush();
  f.close();
  if (!ok) SD.remove(kPath);
  return ok;
}

inline Settings load() {
  Settings s = defaults();
  if (SD.cardType() == CARD_NONE) return s;
  File f = SD.open(kPath, FILE_READ);
  if (!f) return s;
  uint8_t buf[11];
  if (f.read(buf, sizeof(buf)) != sizeof(buf)) { f.close(); return s; }
  f.close();
  if (memcmp(buf, "M5CF", 4) != 0 || buf[4] != 1) return s;
  Settings loaded;
  loaded.language = buf[5];
  loaded.defaultProfile = buf[6];
  loaded.lockTimeoutMs = static_cast<uint32_t>(buf[7]) |
                         (static_cast<uint32_t>(buf[8]) << 8) |
                         (static_cast<uint32_t>(buf[9]) << 16) |
                         (static_cast<uint32_t>(buf[10]) << 24);
  if (!valid(loaded)) return s;
  return loaded;
}

}  // namespace device_settings
