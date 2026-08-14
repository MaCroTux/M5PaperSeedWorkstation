// UI del M5Stack Core2 (320x240, M5Unified/M5GFX, touch FT6336U, botones A/B/C).
//
// Comparte TODA la logica Bitcoin/vault/PSBT/firma con el M5Paper a traves de
// lib/seedworkstation_core. Aqui solo vive display, touch, botones y geometria.
//
// Botones fisicos (ahorran espacio en pantalla):
//   A = ATRAS      B = contexto (borrar/confirmar)      C = contexto (siguiente)

#include <M5Unified.h>
#include <mbedtls/sha256.h>
#include <esp_system.h>
#include "platform/platform.hpp"
#include "lang.hpp"
#include "device_settings.hpp"
#include "bip39_support.hpp"
#include "bitcoin_fingerprint.hpp"
#include "bitcoin_hd.hpp"
#include "bitcoin_address.hpp"
#include "ble_key.hpp"
#include "ble_key_server.hpp"

namespace {

struct Rect { int x, y, w, h; };
inline bool contains(const Rect& r, int x, int y) {
  return x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
}
inline bool headerBackHit(int x, int y) { return y < 26 && x < 44; }

enum class Screen { menu, length, keyboard, review, active_seed, dice, address,
                    settings, settings_lang, locked, stub,
                    key_idle, key_pin, key_result, key_pair_request, key_pair_result };

// Semilla.
uint16_t words[24] = {};
uint8_t wordCount = 0;
uint8_t targetWords = 0;
String prefix = "";
int editingWord = -1;
bool fingerprintValid = false;
char activeFingerprint[14] = "FPR: --------";
bool fingerprintSelfTest = false;
uint8_t reviewPage = 0;

// Dados.
uint16_t diceRolls = 0;
uint16_t diceTarget = 50;
uint8_t diceTargetWords = 12;
uint8_t diceState[32] = {};
uint8_t diceLastRoll = 0;

// Direcciones.
uint32_t addressIndex = 0;
uint8_t addressChange = 0;
String activeAddress = "";

device_settings::Settings gSettings;

// BLE key (llave criptografica).
ble_key::BleKeyServer keyServer;
bool keyMode = false;
bool keyResultAuthorized = false;
bool keyPairResultOk = false;

Screen screen = Screen::menu;
int selected = -1;

void drawScreen();

// ---- dibujo ----

void drawButton(const Rect& r, const char* label, bool sel = false, uint8_t size = 1) {
  M5.Display.fillRoundRect(r.x, r.y, r.w, r.h, 6, sel ? kBlack : kWhite);
  M5.Display.drawRoundRect(r.x, r.y, r.w, r.h, 6, kBlack);
  M5.Display.setTextColor(sel ? kWhite : kBlack, sel ? kBlack : kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(size);
  M5.Display.drawString(lang::tr(label), r.x + r.w / 2, r.y + r.h / 2);
}

void drawHeader(const char* title, bool withBack = false) {
  M5.Display.fillRect(0, 0, DEVICE_WIDTH, 26, kBlack);
  M5.Display.setTextColor(kWhite, kBlack);
  M5.Display.setTextSize(1);
  if (withBack) {
    M5.Display.setTextDatum(middle_left);
    M5.Display.drawString("<", 10, 13);
  }
  M5.Display.setTextDatum(middle_center);
  M5.Display.drawString(title, DEVICE_WIDTH / 2, 13);
  if (fingerprintValid) {
    M5.Display.setTextDatum(middle_right);
    M5.Display.drawString(activeFingerprint + 4, DEVICE_WIDTH - 6, 13);
  }
}

void drawFooter(const char* a, const char* b, const char* c) {
  M5.Display.fillRect(0, DEVICE_HEIGHT - 14, DEVICE_WIDTH, 14, kBlack);
  M5.Display.setTextColor(kWhite, kBlack);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(1);
  char buf[64];
  snprintf(buf, sizeof(buf), "A:%s   B:%s   C:%s", a, b, c);
  M5.Display.drawString(buf, DEVICE_WIDTH / 2, DEVICE_HEIGHT - 7);
}

// ---- semilla ----

void clearFingerprint() {
  fingerprintValid = false;
  memcpy(activeFingerprint, "FPR: --------", 14);
}

bool updateFingerprint() {
  clearFingerprint();
  if (!fingerprintSelfTest || wordCount != targetWords ||
      !bip39::checksum_valid(words, targetWords)) return false;
  uint8_t raw[4] = {};
  if (!bitcoin_fingerprint::calculate(words, targetWords, raw, "")) return false;
  snprintf(activeFingerprint, sizeof(activeFingerprint), "FPR: %02X%02X%02X%02X",
           raw[0], raw[1], raw[2], raw[3]);
  memset(raw, 0, sizeof(raw));
  fingerprintValid = true;
  return true;
}

void resetPhrase(uint8_t count) {
  targetWords = count;
  wordCount = 0;
  prefix = "";
  editingWord = -1;
  reviewPage = 0;
  clearFingerprint();
}

// ---- menu ----

constexpr Rect kMenu[8] = {
  {5, 30, 152, 42}, {163, 30, 152, 42},
  {5, 78, 152, 42}, {163, 78, 152, 42},
  {5, 126, 152, 42}, {163, 126, 152, 42},
  {5, 174, 152, 42}, {163, 174, 152, 42},
};
constexpr const char* kMenuKeys[8] = {
  "INTRODUCIR SEMILLA", "GENERAR ENTROPIA", "VAULT DE SESION", "RECIBIR POR WIFI",
  "HISTORIAL", "AJUSTES", "BLOQUEAR", "LLAVE BLE",
};

void drawMenu() {
  M5.Display.fillScreen(kWhite);
  drawHeader("SEED WORKSTATION");
  for (int i = 0; i < 8; ++i) drawButton(kMenu[i], kMenuKeys[i], selected == i);
}

// ---- longitud ----

void drawLength() {
  M5.Display.fillScreen(kWhite);
  drawHeader(lang::tr("LONGITUD"), true);
  drawButton({30, 70, 120, 80}, "12 PALABRAS", false, 1);
  drawButton({170, 70, 120, 80}, "24 PALABRAS", false, 1);
  drawFooter(lang::tr("ATRAS"), "", "");
}

// ---- teclado BIP39 ----

const char* kRows[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};

void drawKeyboard() {
  M5.Display.fillScreen(kWhite);
  char t[24];
  snprintf(t, sizeof(t), "WORD %u/%u", wordCount + 1, targetWords);
  drawHeader(t, true);

  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString(prefix.length() ? prefix.c_str() : "_", DEVICE_WIDTH / 2, 40);

  uint16_t matches[4] = {};
  const size_t total = bip39::find_matches(prefix, matches, 4);
  for (size_t i = 0; i < total && i < 4; ++i) {
    const Rect r = {i < 2 ? 4 : 164, 54 + (i % 2) * 22, 152, 20};
    drawButton(r, bip39::word_at(matches[i]), false, 1);
  }

  int y = 104;
  for (int row = 0; row < 3; ++row) {
    const char* s = kRows[row];
    const int n = strlen(s);
    const int w = 30;
    int x = (DEVICE_WIDTH - n * w) / 2;
    for (int i = 0; i < n; ++i) {
      char c[2] = {s[i], 0};
      drawButton({x, y, w - 2, 30}, c, false, 1);
      x += w;
    }
    y += 34;
  }
  drawFooter(lang::tr("ATRAS"), lang::tr("BORRAR"), lang::tr("SIGUIENTE"));
}

void keyboardCommit() {
  if (prefix.length() == 0) return;
  const uint16_t idx = bip39::find_exact(prefix);
  if (idx != bip39::kInvalidWord && wordCount < targetWords) {
    words[wordCount++] = idx;
    prefix = "";
    if (wordCount >= targetWords) { screen = Screen::review; drawScreen(); }
    else drawKeyboard();
  }
}

// ---- revision (paginada) ----

void drawReview() {
  M5.Display.fillScreen(kWhite);
  drawHeader(lang::tr("REVISION"), true);
  const uint8_t perPage = 8;
  const uint8_t pages = (targetWords + perPage - 1) / perPage;
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(top_left);
  M5.Display.setTextSize(1);
  int y = 30;
  for (uint8_t i = 0; i < perPage; ++i) {
    const uint8_t wi = reviewPage * perPage + i;
    if (wi >= targetWords) break;
    char line[32];
    snprintf(line, sizeof(line), "%02u %s", wi + 1, bip39::word_at(words[wi]));
    M5.Display.drawString(line, 8, y);
    y += 16;
  }
  const bool valid = bip39::checksum_valid(words, targetWords);
  char pageStr[16];
  snprintf(pageStr, sizeof(pageStr), "%u/%u", reviewPage + 1, pages);
  drawButton({4, 180, 60, 30}, "ANTERIOR", false, 1);
  drawButton({70, 180, 180, 30}, pageStr, false, 1);
  drawButton({256, 180, 60, 30}, "SIGUIENTE", false, 1);
  drawButton({4, 180 + 34, 312, 30}, valid ? "CREAR SEMILLA" : "CHECKSUM INVALIDO", valid, 1);
  drawFooter(lang::tr("ATRAS"), valid ? "CREAR" : "", lang::tr("SIGUIENTE"));
}

// ---- semilla activa ----

void drawActiveSeed() {
  M5.Display.fillScreen(kWhite);
  drawHeader("SEMILLA ACTIVA", true);
  drawButton({5, 40, 152, 44}, "VER CLAVE PUBLICA", false, 1);
  drawButton({163, 40, 152, 44}, "BACKUP SEED", false, 1);
  drawButton({5, 94, 152, 44}, "PASSPHRASE", false, 1);
  drawButton({163, 94, 152, 44}, "EXPLORAR DIRECCIONES", false, 1);
  drawButton({5, 150, 152, 44}, "RECIBIR POR WIFI", false, 1);
  drawButton({163, 150, 152, 44}, "AJUSTES", false, 1);
  drawButton({5, 204, 310, 28}, "VOLVER AL MENU", false, 1);
}

// ---- dados ----

void initDice(uint8_t count) {
  diceTargetWords = count;
  diceTarget = count == 24 ? 100 : 50;
  diceRolls = 0;
  diceLastRoll = 0;
  memset(diceState, 0, sizeof(diceState));
}

void registerDiceRoll(uint8_t value) {
  if (diceRolls >= diceTarget) return;
  uint8_t material[96] = {};
  memcpy(material, diceState, 32);
  memcpy(material + 32, "SEEDWS-DICE-V1-SAMPLE", 21);
  const uint32_t values[4] = {diceRolls, value, millis(), micros()};
  memcpy(material + 60, values, sizeof(values));
  uint32_t rw[5] = {};
  for (uint8_t i = 0; i < 5; ++i) rw[i] = esp_random();
  memcpy(material + 76, rw, sizeof(rw));
  mbedtls_sha256_ret(material, sizeof(material), diceState, 0);
  bitcoin_hd::wipe(material, sizeof(material));
  bitcoin_hd::wipe(rw, sizeof(rw));
  ++diceRolls;
  diceLastRoll = value;
}

void finishDice() {
  if (diceRolls < diceTarget) return;
  uint8_t fr[64] = {}, fin[128] = {}, ent[32] = {};
  esp_fill_random(fr, sizeof(fr));
  memcpy(fin, diceState, sizeof(diceState));
  memcpy(fin + 32, "SEEDWS-DICE-V1-FINAL", 20);
  memcpy(fin + 64, fr, sizeof(fr));
  mbedtls_sha256_ret(fin, sizeof(fin), ent, 0);
  const size_t bytes = diceTargetWords == 12 ? 16 : 32;
  if (!bip39::from_entropy(ent, bytes, words, diceTargetWords)) return;
  targetWords = diceTargetWords;
  wordCount = targetWords;
  prefix = "";
  reviewPage = 0;
  updateFingerprint();
  bitcoin_hd::wipe(diceState, sizeof(diceState));
  bitcoin_hd::wipe(fr, sizeof(fr));
  bitcoin_hd::wipe(fin, sizeof(fin));
  bitcoin_hd::wipe(ent, sizeof(ent));
  screen = Screen::review; drawScreen();
}

void drawDice() {
  M5.Display.fillScreen(kWhite);
  drawHeader("TIRAR DADOS", true);
  char c[24];
  snprintf(c, sizeof(c), "ROLL %u/%u", diceRolls, diceTarget);
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString(c, DEVICE_WIDTH / 2, 40);
  if (diceLastRoll) {
    char l[16];
    snprintf(l, sizeof(l), "Ultimo: %u", diceLastRoll);
    M5.Display.drawString(l, DEVICE_WIDTH / 2, 62);
  }
  const char* faces[6] = {"1", "2", "3", "4", "5", "6"};
  for (int i = 0; i < 6; ++i) {
    const Rect r = {(i % 3) * 104 + 6, 84 + (i / 3) * 54, 96, 48};
    drawButton(r, faces[i], false, 2);
  }
  drawButton({4, 180, 150, 30}, "12 PALABRAS", diceTargetWords == 12, 1);
  drawButton({166, 180, 150, 30}, "24 PALABRAS", diceTargetWords == 24, 1);
  drawFooter(lang::tr("ATRAS"), lang::tr("CREAR"), "");
}

// ---- direcciones ----

void updateAddress() {
  activeAddress = "";
  bitcoin_address::derive(words, targetWords, 84, addressChange, addressIndex, activeAddress);
}

void drawAddress() {
  M5.Display.fillScreen(kWhite);
  drawHeader("DIRECCIONES", true);
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(1);
  char idx[24];
  snprintf(idx, sizeof(idx), "%s #%u", addressChange ? "CAMBIO" : "RECIBIR", addressIndex);
  M5.Display.drawString(idx, DEVICE_WIDTH / 2, 40);
  // Direccion (mono, truncada en 2 lineas).
  String a = activeAddress.length() ? activeAddress : "----";
  M5.Display.setTextSize(1);
  M5.Display.drawString(a.substring(0, 28).c_str(), DEVICE_WIDTH / 2, 70);
  if (a.length() > 28) M5.Display.drawString(a.substring(28).c_str(), DEVICE_WIDTH / 2, 86);
  drawButton({4, 110, 152, 40}, "RECIBIR", addressChange == 0, 1);
  drawButton({164, 110, 152, 40}, "CAMBIO", addressChange == 1, 1);
  drawButton({4, 160, 70, 40}, "-", false, 2);
  drawButton({125, 160, 70, 40}, "+", false, 2);
  drawFooter(lang::tr("ATRAS"), "", "+");
}

// ---- ajustes ----

void drawSettings() {
  M5.Display.fillScreen(kWhite);
  drawHeader(lang::tr("AJUSTES"), true);
  String langLabel = String(lang::tr("Idioma")) + ": " +
      (gSettings.language == 1 ? lang::tr("Espanol") : lang::tr("Ingles"));
  drawButton({5, 40, 310, 40}, langLabel.c_str(), false, 1);
  String lockLabel = String(lang::tr("Bloqueo")) + ": " +
      (gSettings.lockTimeoutMs == 0 ? lang::tr("Nunca")
       : String(gSettings.lockTimeoutMs / 60000) + " min");
  drawButton({5, 88, 310, 40}, lockLabel.c_str(), false, 1);
  drawButton({5, 136, 310, 40}, lang::tr("Estado de la radio"), false, 1);
  drawFooter(lang::tr("ATRAS"), "", "");
}

void drawSettingsLang() {
  M5.Display.fillScreen(kWhite);
  drawHeader(lang::tr("Idioma"), true);
  drawButton({5, 40, 310, 44}, lang::tr("Ingles"), gSettings.language == 0, 1);
  drawButton({5, 94, 310, 44}, lang::tr("Espanol"), gSettings.language == 1, 1);
  drawFooter(lang::tr("ATRAS"), "", "");
}

// ---- bloqueo ----

void drawLocked() {
  M5.Display.fillScreen(kBlack);
  M5.Display.setTextColor(kWhite, kBlack);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(3);
  M5.Display.drawString("BLOQUEADO", DEVICE_WIDTH / 2, 100);
  M5.Display.setTextSize(1);
  M5.Display.drawString(lang::tr("Pulsa para desbloquear"), DEVICE_WIDTH / 2, 140);
}

// ---- stub ----

void drawStub() {
  M5.Display.fillScreen(kWhite);
  drawHeader("EN DESARROLLO", true);
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString("Proximamente", DEVICE_WIDTH / 2, 110);
  drawFooter(lang::tr("ATRAS"), "", "");
}

// ---- BLE key (llave criptografica) ----

void drawKeyHeader(const char* title) {
  M5.Display.fillRect(0, 0, DEVICE_WIDTH, 26, kBlack);
  M5.Display.setTextColor(kWhite, kBlack);
  M5.Display.setTextSize(1);
  M5.Display.setTextDatum(middle_center);
  M5.Display.drawString(title, DEVICE_WIDTH / 2, 13);
}

void drawKeyIdle() {
  M5.Display.fillScreen(kBlack);
  M5.Display.setTextColor(kWhite, kBlack);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString("M5 VAULT KEY", DEVICE_WIDTH / 2, 70);
  M5.Display.setTextSize(3);
  M5.Display.drawString("LOCKED", DEVICE_WIDTH / 2, 120);
  M5.Display.setTextSize(1);
  M5.Display.drawString(keyServer.hasPin() ? "PIN SET - Waiting..." : "NO PIN - Waiting...",
                        DEVICE_WIDTH / 2, 170);
  drawFooter("", "", "");
}

constexpr Rect kPinKey[12] = {
  {15, 92, 70, 46}, {90, 92, 70, 46}, {165, 92, 70, 46}, {240, 92, 70, 46},
  {15, 145, 70, 46}, {90, 145, 70, 46}, {165, 145, 70, 46}, {240, 145, 70, 46},
  {15, 198, 70, 46}, {90, 198, 70, 46}, {165, 198, 70, 46}, {240, 198, 70, 46}};
constexpr const char* kPinLabels[12] =
    {"1", "2", "3", "DEL", "4", "5", "6", "OK", "7", "8", "9", "0"};

void drawKeyPin() {
  M5.Display.fillScreen(kWhite);
  const auto pin = keyServer.pinState();
  const bool set = pin == ble_key::BleKeyServer::PinState::SetEntry ||
                   pin == ble_key::BleKeyServer::PinState::SetConfirm;
  drawKeyHeader(set ? "SET PIN" : "ENTER PIN");
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(1);
  if (pin == ble_key::BleKeyServer::PinState::SetConfirm)
    M5.Display.drawString("Repite el PIN", DEVICE_WIDTH / 2, 38);
  else if (pin == ble_key::BleKeyServer::PinState::UnlockEntry)
    M5.Display.drawString("PIN de 6 digitos", DEVICE_WIDTH / 2, 38);
  else
    M5.Display.drawString("Crea un PIN de 6 digitos", DEVICE_WIDTH / 2, 38);
  M5.Display.drawRoundRect(60, 52, 200, 28, 6, kBlack);
  M5.Display.setTextSize(2);
  char dots[7] = {};
  const size_t n = strlen(keyServer.pinBuffer());
  for (size_t i = 0; i < 6; ++i) dots[i] = i < n ? '*' : ' ';
  M5.Display.drawString(dots, DEVICE_WIDTH / 2, 66);
  for (int i = 0; i < 12; ++i)
    drawButton(kPinKey[i], kPinLabels[i], false, 2);
}

void drawKeyResult() {
  M5.Display.fillScreen(kWhite);
  drawKeyHeader("RESULT");
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString(keyResultAuthorized ? "ACCESS AUTHORIZED" : "ACCESS DENIED",
                        DEVICE_WIDTH / 2, 110);
}

void drawKeyPairRequest() {
  M5.Display.fillScreen(kWhite);
  drawKeyHeader("PAIR REQUEST");
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString("M5Paper", DEVICE_WIDTH / 2, 60);
  M5.Display.setTextSize(1);
  M5.Display.drawString("quiere registrar esta llave", DEVICE_WIDTH / 2, 92);
  drawButton({10, 130, 145, 55}, "CANCEL", false, 2);
  drawButton({165, 130, 145, 55}, "AUTHORIZE", false, 2);
  drawFooter("", "CANCEL", "AUTHORIZE");
}

void drawKeyPairResult() {
  M5.Display.fillScreen(kWhite);
  drawKeyHeader("RESULT");
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString(keyPairResultOk ? "PAIRED" : "PAIR DENIED",
                        DEVICE_WIDTH / 2, 110);
}

void enterKeyMode() {
  if (!keyServer.begin()) {
    Serial.println("[BLEKEY] server begin failed");
    screen = Screen::menu; drawScreen();
    return;
  }
  keyMode = true;
  screen = Screen::key_idle;
  drawScreen();
}

void loopKeyMode() {
  keyServer.update();

  const auto st = keyServer.state();
  const auto pst = keyServer.pairState();
  const auto pin = keyServer.pinState();

  if (pst == ble_key::BleKeyServer::PairState::Requested &&
      screen != Screen::key_pair_request) {
    screen = Screen::key_pair_request; drawScreen();
  } else if ((pst == ble_key::BleKeyServer::PairState::Authorized ||
              pst == ble_key::BleKeyServer::PairState::Denied ||
              pst == ble_key::BleKeyServer::PairState::Timeout) &&
             screen != Screen::key_pair_result) {
    keyPairResultOk = (pst == ble_key::BleKeyServer::PairState::Authorized);
    screen = Screen::key_pair_result; drawScreen();
  } else if (pst == ble_key::BleKeyServer::PairState::Idle &&
             screen == Screen::key_pair_result) {
    screen = Screen::key_idle; drawScreen();
  } else if ((pin == ble_key::BleKeyServer::PinState::SetEntry ||
              pin == ble_key::BleKeyServer::PinState::SetConfirm ||
              pin == ble_key::BleKeyServer::PinState::UnlockEntry) &&
             screen != Screen::key_pin) {
    screen = Screen::key_pin; drawScreen();
  } else if (st == ble_key::BleKeyServer::State::Authorized &&
             screen != Screen::key_result) {
    keyResultAuthorized = true; screen = Screen::key_result; drawScreen();
  } else if ((st == ble_key::BleKeyServer::State::Denied ||
              st == ble_key::BleKeyServer::State::Timeout) &&
             screen != Screen::key_result) {
    keyResultAuthorized = false; screen = Screen::key_result; drawScreen();
  } else if (st == ble_key::BleKeyServer::State::Idle &&
             screen == Screen::key_result) {
    screen = Screen::key_idle; drawScreen();
  } else if (pin == ble_key::BleKeyServer::PinState::Done &&
             screen == Screen::key_pin) {
    screen = Screen::key_idle; drawScreen();
  }

  auto t = M5.Touch.getDetail();
  if (t.wasPressed()) {
    if (screen == Screen::key_pair_request) {
      if (contains({10, 130, 145, 55}, t.x, t.y)) keyServer.denyPairing();
      else if (contains({165, 130, 145, 55}, t.x, t.y)) keyServer.allowPairing();
    } else if (screen == Screen::key_pin) {
      for (int i = 0; i < 12; ++i) if (contains(kPinKey[i], t.x, t.y)) {
        if (i == 3) keyServer.pinBackspace();
        else if (i == 7) keyServer.pinSubmit();
        else if (i < 3) keyServer.pinDigit(static_cast<char>('1' + i));
        else if (i < 7) keyServer.pinDigit(static_cast<char>('4' + (i - 4)));
        else if (i < 11) keyServer.pinDigit(static_cast<char>('7' + (i - 8)));
        else keyServer.pinDigit('0');
        drawScreen();
        return;
      }
    }
  }
  if (M5.BtnB.wasPressed()) {
    if (screen == Screen::key_pair_request) keyServer.denyPairing();
    else if (screen == Screen::key_pin) keyServer.pinBackspace();
  }
  if (M5.BtnC.wasPressed()) {
    if (screen == Screen::key_pair_request) keyServer.allowPairing();
    else if (screen == Screen::key_pin) keyServer.pinSubmit();
  }
  // Salir del modo llave manteniendo A pulsado.
  if (M5.BtnA.pressedFor(600)) {
    keyMode = false;
    screen = Screen::menu; drawScreen();
  }
}

void drawScreen() {
  switch (screen) {
    case Screen::menu: drawMenu(); break;
    case Screen::length: drawLength(); break;
    case Screen::keyboard: drawKeyboard(); break;
    case Screen::review: drawReview(); break;
    case Screen::active_seed: drawActiveSeed(); break;
    case Screen::dice: drawDice(); break;
    case Screen::address: drawAddress(); break;
    case Screen::settings: drawSettings(); break;
    case Screen::settings_lang: drawSettingsLang(); break;
    case Screen::locked: drawLocked(); break;
    case Screen::key_idle: drawKeyIdle(); break;
    case Screen::key_pin: drawKeyPin(); break;
    case Screen::key_result: drawKeyResult(); break;
    case Screen::key_pair_request: drawKeyPairRequest(); break;
    case Screen::key_pair_result: drawKeyPairResult(); break;
    default: drawStub(); break;
  }
}

// ---- navegacion ----

void goBack() {
  switch (screen) {
    case Screen::length: screen = Screen::menu; break;
    case Screen::keyboard: screen = Screen::menu; break;
    case Screen::review: screen = Screen::keyboard; break;
    case Screen::active_seed: screen = Screen::menu; break;
    case Screen::dice: screen = Screen::length; break;
    case Screen::address: screen = Screen::active_seed; break;
    case Screen::settings: screen = Screen::menu; break;
    case Screen::settings_lang: screen = Screen::settings; break;
    default: screen = Screen::menu; break;
  }
  drawScreen();
}

void tap(int x, int y) {
  if (screen != Screen::menu && headerBackHit(x, y)) { goBack(); return; }

  switch (screen) {
    case Screen::menu: {
      if (contains(kMenu[0], x, y)) { resetPhrase(12); screen = Screen::length; drawScreen(); }
      else if (contains(kMenu[1], x, y)) { initDice(12); screen = Screen::dice; drawScreen(); }
      else if (contains(kMenu[5], x, y)) { screen = Screen::settings; drawScreen(); }
      else if (contains(kMenu[6], x, y)) { screen = Screen::locked; drawScreen(); }
      else if (contains(kMenu[7], x, y)) { enterKeyMode(); }
      else {
        for (int i = 0; i < 8; ++i)
          if (contains(kMenu[i], x, y)) { selected = i; screen = Screen::stub; drawScreen(); }
      }
      break;
    }
    case Screen::length:
      if (contains({30, 70, 120, 80}, x, y)) { resetPhrase(12); screen = Screen::keyboard; drawScreen(); }
      else if (contains({170, 70, 120, 80}, x, y)) { resetPhrase(24); screen = Screen::keyboard; drawScreen(); }
      break;
    case Screen::keyboard: {
      uint16_t matches[4] = {};
      const size_t total = bip39::find_matches(prefix, matches, 4);
      for (size_t i = 0; i < total && i < 4; ++i) {
        const Rect r = {i < 2 ? 4 : 164, 54 + (i % 2) * 22, 152, 20};
        if (contains(r, x, y)) {
          if (wordCount < targetWords) {
            words[wordCount++] = matches[i]; prefix = "";
            if (wordCount >= targetWords) { screen = Screen::review; drawScreen(); }
            else drawKeyboard();
          }
          return;
        }
      }
      int y0 = 104;
      for (int row = 0; row < 3; ++row) {
        const char* s = kRows[row];
        const int n = strlen(s);
        const int w = 30;
        int x0 = (DEVICE_WIDTH - n * w) / 2;
        for (int i = 0; i < n; ++i) {
          if (contains({x0, y0, w - 2, 30}, x, y)) {
            if (prefix.length() < 8) { prefix += s[i]; drawKeyboard(); }
            return;
          }
          x0 += w;
        }
        y0 += 34;
      }
      break;
    }
    case Screen::review: {
      const uint8_t perPage = 8;
      const uint8_t pages = (targetWords + perPage - 1) / perPage;
      const bool valid = bip39::checksum_valid(words, targetWords);
      if (contains({4, 180, 60, 30}, x, y)) { if (reviewPage > 0) { --reviewPage; drawReview(); } }
      else if (contains({256, 180, 60, 30}, x, y)) { if (reviewPage + 1 < pages) { ++reviewPage; drawReview(); } }
      else if (contains({4, 214, 312, 30}, x, y) && valid) { updateFingerprint(); screen = Screen::active_seed; drawScreen(); }
      break;
    }
    case Screen::active_seed:
      if (contains({5, 204, 310, 28}, x, y)) { screen = Screen::menu; drawScreen(); }
      else if (contains({163, 94, 152, 44}, x, y)) { updateAddress(); screen = Screen::address; drawScreen(); }
      else if (contains({163, 150, 152, 44}, x, y)) { screen = Screen::settings; drawScreen(); }
      else screen = Screen::stub, drawScreen();
      break;
    case Screen::dice: {
      const char* faces[6] = {"1", "2", "3", "4", "5", "6"};
      for (int i = 0; i < 6; ++i) {
        const Rect r = {(i % 3) * 104 + 6, 84 + (i / 3) * 54, 96, 48};
        if (contains(r, x, y)) { registerDiceRoll(i + 1); drawDice(); return; }
      }
      if (contains({4, 180, 150, 30}, x, y)) { initDice(12); drawDice(); }
      else if (contains({166, 180, 150, 30}, x, y)) { initDice(24); drawDice(); }
      break;
    }
    case Screen::address:
      if (contains({4, 110, 152, 40}, x, y)) { addressChange = 0; updateAddress(); drawAddress(); }
      else if (contains({164, 110, 152, 40}, x, y)) { addressChange = 1; updateAddress(); drawAddress(); }
      else if (contains({4, 160, 70, 40}, x, y)) { if (addressIndex > 0) { --addressIndex; updateAddress(); drawAddress(); } }
      else if (contains({125, 160, 70, 40}, x, y)) { ++addressIndex; updateAddress(); drawAddress(); }
      break;
    case Screen::settings:
      if (contains({5, 40, 310, 40}, x, y)) { screen = Screen::settings_lang; drawScreen(); }
      else if (contains({5, 136, 310, 40}, x, y)) { screen = Screen::stub; drawScreen(); }
      break;
    case Screen::settings_lang:
      if (contains({5, 40, 310, 44}, x, y)) { gSettings.language = 0; lang::set(lang::Lang::EN); device_settings::save(gSettings); drawSettingsLang(); }
      else if (contains({5, 94, 310, 44}, x, y)) { gSettings.language = 1; lang::set(lang::Lang::ES); device_settings::save(gSettings); drawSettingsLang(); }
      break;
    case Screen::locked:
      screen = Screen::menu; drawScreen();
      break;
    default:
      break;
  }
}

// Botones fisicos: A=atras, B=contexto, C=contexto.
void btnA() { goBack(); }

void btnB() {
  switch (screen) {
    case Screen::keyboard:  // B = borrar
      if (prefix.length()) { prefix.remove(prefix.length() - 1); drawKeyboard(); }
      break;
    case Screen::review:    // B = crear
      if (bip39::checksum_valid(words, targetWords)) { updateFingerprint(); screen = Screen::active_seed; drawScreen(); }
      break;
    case Screen::dice:      // B = crear
      finishDice();
      break;
    default: break;
  }
}

void btnC() {
  switch (screen) {
    case Screen::keyboard:  // C = siguiente
      keyboardCommit();
      break;
    case Screen::review: {  // C = siguiente pagina
      const uint8_t perPage = 8;
      const uint8_t pages = (targetWords + perPage - 1) / perPage;
      if (reviewPage + 1 < pages) { ++reviewPage; drawReview(); }
      break;
    }
    case Screen::address:   // C = siguiente direccion
      ++addressIndex; updateAddress(); drawAddress();
      break;
    default: break;
  }
}

}  // namespace

void setup() {
  M5.begin();
  M5.Display.setRotation(1);
  fingerprintSelfTest = bitcoin_fingerprint::self_test();
  gSettings = device_settings::load();
  lang::set(gSettings.language == 1 ? lang::Lang::ES : lang::Lang::EN);
  drawScreen();
}

void loop() {
  M5.update();
  if (keyMode) { loopKeyMode(); return; }
  auto t = M5.Touch.getDetail();
  if (t.wasPressed()) tap(t.x, t.y);
  if (M5.BtnA.wasPressed()) btnA();
  if (M5.BtnB.wasPressed()) btnB();
  if (M5.BtnC.wasPressed()) btnC();
}
