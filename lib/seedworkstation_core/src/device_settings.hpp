#pragma once
#include <Arduino.h>
#include <SD.h>
#include <string.h>

// Configuracion persistente del dispositivo, guardada en la SD.
// Formato del fichero (17 bytes, version 4):
//   [0..3]   magia "M5CF"
//   [4]      version = 4
//   [5]      idioma (0 = ingles, 1 = espanol)
//   [6]      derivacion por defecto (0..2 = BIP44/49/84)
//   [7..10]  tiempo de bloqueo en ms (uint32 LE; 0 = nunca)
//   [11..14] tiempo de limpieza de seed en ms (uint32 LE; 0 = nunca)
//   [15]     limpieza de pantalla (0 = nunca; N = cada N refrescos)
//   [16]     direcciones por lado a consultar en mempool.space (10/20/50/100)
//
// Se aceptan tambien los formatos antiguos (version 2 y 3) rellenando los
// campos nuevos con sus valores por defecto.

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

// Opciones de limpieza de seed (ms). 0 = nunca.
constexpr uint32_t kCleanNone = 0;
constexpr uint32_t kClean10m = 600000;
constexpr uint32_t kClean30m = 1800000;
constexpr uint32_t kClean60m = 3600000;

constexpr uint32_t kCleanOptions[] = {kClean10m, kClean30m, kClean60m, kCleanNone};
constexpr uint8_t kCleanOptionCount = sizeof(kCleanOptions) / sizeof(kCleanOptions[0]);

// Limpieza automatica de pantalla: cada cuantos refrescos completos se hace un
// Clear del panel. 0 = nunca.
constexpr uint8_t kScreenCleanNever = 0;
constexpr uint8_t kScreenCleanOptions[] = {0, 5, 7, 10, 20};
constexpr uint8_t kScreenCleanOptionCount =
    sizeof(kScreenCleanOptions) / sizeof(kScreenCleanOptions[0]);

// Direcciones por lado (recibir/cambio) a consultar en mempool.space.
constexpr uint8_t kBalanceAddrOptions[] = {10, 20, 50, 100};
constexpr uint8_t kBalanceAddrOptionCount =
    sizeof(kBalanceAddrOptions) / sizeof(kBalanceAddrOptions[0]);

// Gap limit: dejar de consultar al encontrar N direcciones vacias consecutivas.
constexpr uint8_t kGapOptions[] = {5, 10, 20, 50};
constexpr uint8_t kGapOptionCount = sizeof(kGapOptions) / sizeof(kGapOptions[0]);

struct Settings {
  uint8_t language;          // 0 = EN, 1 = ES
  uint8_t defaultProfile;    // 0..3
  uint32_t lockTimeoutMs;    // 0 = nunca
  uint32_t seedCleanTimeoutMs;  // 0 = nunca
  uint8_t screenCleanEvery;  // 0 = nunca, N = cada N refrescos
  uint8_t balanceAddrPerSide;   // direcciones por lado a consultar
  uint8_t balanceGapLimit;      // gap limit (direcciones vacias consecutivas)
  uint8_t onlineEnabled;        // 0 = billetera fria (por defecto), 1 = billetera online
  uint8_t wordlistLanguage;     // 0 = BIP39 ingles, 1 = BIP39 espanol
};

inline Settings defaults() {
  Settings s;
  s.language = 0;
  s.defaultProfile = 2;  // BIP84
  s.lockTimeoutMs = kTimeout3m;
  s.seedCleanTimeoutMs = kCleanNone;
  s.screenCleanEvery = 7;
  s.balanceAddrPerSide = 50;
  s.balanceGapLimit = 20;
  s.onlineEnabled = 0;  // fria por defecto
  s.wordlistLanguage = 0;  // BIP39 ingles por defecto
  return s;
}

inline bool valid(const Settings& s) {
  if (s.language > 1 || s.defaultProfile > 2) return false;
  bool lockOk = false;
  if (s.lockTimeoutMs == kTimeoutNone) lockOk = true;
  else for (uint8_t i = 0; i < kTimeoutOptionCount; ++i)
    if (s.lockTimeoutMs == kTimeoutOptions[i]) { lockOk = true; break; }
  bool cleanOk = false;
  if (s.seedCleanTimeoutMs == kCleanNone) cleanOk = true;
  else for (uint8_t i = 0; i < kCleanOptionCount; ++i)
    if (s.seedCleanTimeoutMs == kCleanOptions[i]) { cleanOk = true; break; }
  bool screenOk = false;
  for (uint8_t i = 0; i < kScreenCleanOptionCount; ++i)
    if (s.screenCleanEvery == kScreenCleanOptions[i]) { screenOk = true; break; }
  bool balanceOk = false;
  for (uint8_t i = 0; i < kBalanceAddrOptionCount; ++i)
    if (s.balanceAddrPerSide == kBalanceAddrOptions[i]) { balanceOk = true; break; }
  bool gapOk = false;
  for (uint8_t i = 0; i < kGapOptionCount; ++i)
    if (s.balanceGapLimit == kGapOptions[i]) { gapOk = true; break; }
  if (s.onlineEnabled > 1) return false;
  if (s.wordlistLanguage > 1) return false;
  return lockOk && cleanOk && screenOk && balanceOk && gapOk;
}

inline bool save(const Settings& s) {
  if (SD.cardType() == CARD_NONE) return false;
  File f = SD.open(kPath, FILE_WRITE);
  if (!f) return false;
  uint8_t buf[20];
  memcpy(buf, "M5CF", 4);
  buf[4] = 7;
  buf[5] = s.language;
  buf[6] = s.defaultProfile;
  buf[7] = s.lockTimeoutMs & 0xFF;
  buf[8] = (s.lockTimeoutMs >> 8) & 0xFF;
  buf[9] = (s.lockTimeoutMs >> 16) & 0xFF;
  buf[10] = (s.lockTimeoutMs >> 24) & 0xFF;
  buf[11] = s.seedCleanTimeoutMs & 0xFF;
  buf[12] = (s.seedCleanTimeoutMs >> 8) & 0xFF;
  buf[13] = (s.seedCleanTimeoutMs >> 16) & 0xFF;
  buf[14] = (s.seedCleanTimeoutMs >> 24) & 0xFF;
  buf[15] = s.screenCleanEvery;
  buf[16] = s.balanceAddrPerSide;
  buf[17] = s.balanceGapLimit;
  buf[18] = s.onlineEnabled;
  buf[19] = s.wordlistLanguage;
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
  uint8_t buf[20] = {};
  const size_t n = f.read(buf, sizeof(buf));
  f.close();
  if (memcmp(buf, "M5CF", 4) != 0) return s;
  Settings loaded = defaults();
  if (buf[4] == 2 && n >= 15) {
    loaded.language = buf[5];
    loaded.defaultProfile = buf[6];
    loaded.lockTimeoutMs = static_cast<uint32_t>(buf[7]) |
                           (static_cast<uint32_t>(buf[8]) << 8) |
                           (static_cast<uint32_t>(buf[9]) << 16) |
                           (static_cast<uint32_t>(buf[10]) << 24);
    loaded.seedCleanTimeoutMs = static_cast<uint32_t>(buf[11]) |
                                (static_cast<uint32_t>(buf[12]) << 8) |
                                (static_cast<uint32_t>(buf[13]) << 16) |
                                (static_cast<uint32_t>(buf[14]) << 24);
  } else if (buf[4] == 3 && n >= 16) {
    loaded.language = buf[5];
    loaded.defaultProfile = buf[6];
    loaded.lockTimeoutMs = static_cast<uint32_t>(buf[7]) |
                           (static_cast<uint32_t>(buf[8]) << 8) |
                           (static_cast<uint32_t>(buf[9]) << 16) |
                           (static_cast<uint32_t>(buf[10]) << 24);
    loaded.seedCleanTimeoutMs = static_cast<uint32_t>(buf[11]) |
                                (static_cast<uint32_t>(buf[12]) << 8) |
                                (static_cast<uint32_t>(buf[13]) << 16) |
                                (static_cast<uint32_t>(buf[14]) << 24);
    loaded.screenCleanEvery = buf[15];
  } else if (buf[4] == 4 && n >= 17) {
    loaded.language = buf[5];
    loaded.defaultProfile = buf[6];
    loaded.lockTimeoutMs = static_cast<uint32_t>(buf[7]) |
                           (static_cast<uint32_t>(buf[8]) << 8) |
                           (static_cast<uint32_t>(buf[9]) << 16) |
                           (static_cast<uint32_t>(buf[10]) << 24);
    loaded.seedCleanTimeoutMs = static_cast<uint32_t>(buf[11]) |
                                (static_cast<uint32_t>(buf[12]) << 8) |
                                (static_cast<uint32_t>(buf[13]) << 16) |
                                (static_cast<uint32_t>(buf[14]) << 24);
    loaded.screenCleanEvery = buf[15];
    loaded.balanceAddrPerSide = buf[16];
  } else if (buf[4] == 5 && n >= 18) {
    loaded.language = buf[5];
    loaded.defaultProfile = buf[6];
    loaded.lockTimeoutMs = static_cast<uint32_t>(buf[7]) |
                           (static_cast<uint32_t>(buf[8]) << 8) |
                           (static_cast<uint32_t>(buf[9]) << 16) |
                           (static_cast<uint32_t>(buf[10]) << 24);
    loaded.seedCleanTimeoutMs = static_cast<uint32_t>(buf[11]) |
                                (static_cast<uint32_t>(buf[12]) << 8) |
                                (static_cast<uint32_t>(buf[13]) << 16) |
                                (static_cast<uint32_t>(buf[14]) << 24);
    loaded.screenCleanEvery = buf[15];
    loaded.balanceAddrPerSide = buf[16];
    loaded.balanceGapLimit = buf[17];
  } else if (buf[4] == 6 && n >= 19) {
    loaded.language = buf[5];
    loaded.defaultProfile = buf[6];
    loaded.lockTimeoutMs = static_cast<uint32_t>(buf[7]) |
                           (static_cast<uint32_t>(buf[8]) << 8) |
                           (static_cast<uint32_t>(buf[9]) << 16) |
                           (static_cast<uint32_t>(buf[10]) << 24);
    loaded.seedCleanTimeoutMs = static_cast<uint32_t>(buf[11]) |
                                (static_cast<uint32_t>(buf[12]) << 8) |
                                (static_cast<uint32_t>(buf[13]) << 16) |
                                (static_cast<uint32_t>(buf[14]) << 24);
    loaded.screenCleanEvery = buf[15];
    loaded.balanceAddrPerSide = buf[16];
    loaded.balanceGapLimit = buf[17];
    loaded.onlineEnabled = buf[18];
  } else if (buf[4] == 7 && n >= 20) {
    loaded.language = buf[5];
    loaded.defaultProfile = buf[6];
    loaded.lockTimeoutMs = static_cast<uint32_t>(buf[7]) |
                           (static_cast<uint32_t>(buf[8]) << 8) |
                           (static_cast<uint32_t>(buf[9]) << 16) |
                           (static_cast<uint32_t>(buf[10]) << 24);
    loaded.seedCleanTimeoutMs = static_cast<uint32_t>(buf[11]) |
                                (static_cast<uint32_t>(buf[12]) << 8) |
                                (static_cast<uint32_t>(buf[13]) << 16) |
                                (static_cast<uint32_t>(buf[14]) << 24);
    loaded.screenCleanEvery = buf[15];
    loaded.balanceAddrPerSide = buf[16];
    loaded.balanceGapLimit = buf[17];
    loaded.onlineEnabled = buf[18];
    loaded.wordlistLanguage = buf[19];
  } else {
    return s;
  }
  if (!valid(loaded)) return s;
  return loaded;
}

}  // namespace device_settings
