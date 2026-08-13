#include <M5EPD.h>
#include <bootloader_random.h>

#include "bip39_support.hpp"
#include "bitcoin_fingerprint.hpp"
#include "bitcoin_hd.hpp"
#include "bitcoin_address.hpp"
#include "encrypted_seed_store.hpp"
#include "session_vault_store.hpp"
#include "qr_ble_client.hpp"
#include "qr_wifi_server.hpp"
#include "psbt_parser.hpp"
#include "tx_sign.hpp"
#include "multisig.hpp"
#include "bbqr.hpp"
#include "lang.hpp"
#include "device_settings.hpp"

// Migracion nativa M5EPD. Solo datos de prueba; no usar fondos reales.

namespace {

constexpr char kVersion[] = "v1.2";
constexpr int kWidth = 540;
constexpr int kHeight = 960;
constexpr int kRockerRightPin = 37;
constexpr int kRockerPressPin = 38;
constexpr int kRockerLeftPin = 39;
constexpr uint8_t kWhite = 0;
constexpr uint8_t kBlack = 15;

enum class Screen { menu, active_seed, seed_switcher, passphrase_input, backup_seed, vault_actions, length, keyboard, review, plain_qr,
                    seedqr, public_key, public_key_qr, entropy_length, entropy, dice,
                    security_warning, vault_password, vault_result,
                    vault_label, address_explorer, address_index_input, address_qr,
                     vault_list, vault_unlock, vault_loaded,
                     session_menu, session_meta_list, session_seed_list,
                     delete_confirm, discard_confirm, session_lock_warning,
                     help, unlock_confirm, diagnostics, scan_qr, wifi_receive,
                     wifi_mode, signed_tx, locked, screensaver, tx_review, utxo_detail, signed_mode,
                     animated_qr, settings, settings_lang, settings_timeout,
                     settings_clean, settings_derivation, settings_radio,
                     multisig_confirm, tx_history };

struct Rect {
  int x, y, w, h;
  bool contains(int px, int py) const {
    return px >= x && px < x + w && py >= y && py < y + h;
  }
};

constexpr Rect kMenu[] = {{40, 152, 460, 66}, {40, 224, 460, 66},
                          {40, 296, 460, 66}, {40, 368, 460, 66},
                          {40, 440, 460, 66}, {40, 512, 460, 66},
                          {40, 584, 460, 66}};
constexpr const char* kMenuLabels[] = {"INTRODUCIR SEMILLA",
                                       "GENERAR ENTROPIA", "VAULT DE SESION",
                                       "RECIBIR POR WIFI", "HISTORIAL", "AJUSTES",
                                       "BLOQUEAR"};
constexpr Rect kHelpIcon{456, 776, 64, 64};
constexpr Rect kChoose12{40, 260, 210, 150};
constexpr Rect kChoose24{290, 260, 210, 150};
constexpr Rect kBack{20, 835, 145, 85};
constexpr Rect kAction{190, 835, 330, 85};
constexpr Rect kDetail{175, 835, 170, 85};
constexpr Rect kFirmar{355, 835, 165, 85};
constexpr Rect kDelete{20, 510, 145, 70};
constexpr Rect kAdd{185, 510, 335, 70};
constexpr Rect kSuggestion[] = {{20, 610, 240, 72}, {280, 610, 240, 72},
                                {20, 700, 240, 72}, {280, 700, 240, 72}};
constexpr Rect kQrPrevious{20, 835, 145, 85};
constexpr Rect kQrBack{190, 835, 160, 85};
constexpr Rect kQrNext{375, 835, 145, 85};
constexpr Rect kPublicQr{150, 720, 240, 80};
constexpr Rect kFingerprintBadge{325, 8, 195, 72};
constexpr Rect kEntropyArea{20, 185, 500, 500};
constexpr Rect kEntropyReset{20, 725, 155, 90};
constexpr Rect kEntropyCreate{190, 725, 330, 90};
constexpr Rect kDiceLength12{30, 195, 235, 52};
constexpr Rect kDiceLength24{275, 195, 235, 52};
constexpr Rect kDiceValue[] = {{30, 330, 150, 80}, {195, 330, 150, 80}, {360, 330, 150, 80},
                               {30, 420, 150, 80}, {195, 420, 150, 80}, {360, 420, 150, 80}};
constexpr Rect kDiceReset{30, 540, 480, 60};
constexpr Rect kActiveMenu[] = {{40, 150, 460, 66}, {40, 222, 460, 66},
                                {40, 294, 460, 66}, {40, 366, 460, 66},
                                {40, 438, 460, 66}, {40, 510, 460, 66},
                                {40, 582, 460, 66}, {40, 654, 460, 66},
                                {40, 726, 460, 66}};
constexpr const char* kActiveLabels[] = {"VER CLAVE PUBLICA", "BACKUP SEED",
                                         "PASSPHRASE", "EXPLORAR DIRECCIONES",
                                         "DESCARTAR SEED"};
constexpr const char* kBackupLabels[] = {"VER PALABRAS", "VER QR",
                                          "BACKUP SEEDQR", "ABRIR VAULT DE SESION",
                                          "VOLVER"};
constexpr Rect kAddressValue{20, 245, 500, 190};
constexpr Rect kAddressReceive{20, 455, 240, 70};
constexpr Rect kAddressChange{280, 455, 240, 70};
constexpr Rect kAddressMinus{20, 545, 145, 70};
constexpr Rect kAddressIndex{185, 545, 170, 70};
constexpr Rect kAddressPlus{375, 545, 145, 70};
constexpr Rect kAddressProfile{20, 640, 500, 75};
constexpr Rect kDigitKey[10] = {{40, 235, 145, 80}, {200, 235, 145, 80},
                                {360, 235, 145, 80}, {40, 330, 145, 80},
                                {200, 330, 145, 80}, {360, 330, 145, 80},
                                {40, 425, 145, 80}, {200, 425, 145, 80},
                                {360, 425, 145, 80}, {200, 520, 145, 80}};
constexpr Rect kDigitDelete{40, 520, 145, 80};
constexpr Rect kVaultReveal{120, 620, 300, 75};
constexpr Rect kPassMode{20, 600, 150, 70};
constexpr Rect kPassSpace{185, 600, 170, 70};
constexpr Rect kPassReveal{370, 600, 150, 70};
constexpr Rect kPassRemove{120, 700, 300, 70};
constexpr Rect kVaultFiles[] = {{30, 170, 480, 80}, {30, 265, 480, 80},
                                {30, 360, 480, 80}, {30, 455, 480, 80},
                                {30, 550, 480, 80}, {30, 645, 480, 80}};
constexpr Rect kSessionNewVault{30, 730, 480, 44};
constexpr Rect kSessionNewEntropy{30, 782, 480, 44};
constexpr Rect kSessionNewRam{30, 834, 480, 44};
constexpr Rect kSessionBack{30, 886, 225, 40};
constexpr Rect kSessionAction{265, 886, 245, 40};

struct KeyRow { const char* letters; int x, y, width; };
constexpr KeyRow kRows[] = {{"QWERTYUIOP", 10, 265, 52},
                            {"ASDFGHJKL", 34, 345, 52},
                            {"ZXCVBNM", 60, 425, 60}};

M5EPD_Canvas page(&M5.EPD);
M5EPD_Canvas entropyCanvas(&M5.EPD);
Screen screen = Screen::menu;
Screen securityWarningReturn = Screen::review;
Screen securityWarningTarget = Screen::review;
void requestSecurity(Screen target, Screen returnTo);
void drawScreen();
uint8_t focusIndex = 0;
uint8_t targetWords = 12;
uint8_t wordCount = 0;
int8_t editingWord = -1;
uint16_t words[24] = {};
String prefix;
QRCode seedqr;
uint8_t seedqrBuffer[128] = {};
uint8_t seedqrRow = 0;
uint8_t seedqrRun = 0;
QRCode publicKeyQr;
uint8_t publicKeyQrBuffer[512] = {};
String publicExtendedKey;
uint8_t publicKeyProfile = 0;
uint8_t entropyState[32] = {};
uint16_t entropySamples = 0;
constexpr uint16_t kEntropyTarget = 128;
constexpr uint16_t kDiceTarget12 = 50;
constexpr uint16_t kDiceTarget24 = 100;
bool entropyCanvasReady = false;
bool entropySourceActive = false;
bool entropyHealthOk = true;
uint32_t entropyLastRandom = 0;
int entropyLastX = -1;
uint8_t diceState[32] = {};
uint16_t diceRolls = 0;
uint16_t diceTarget = kDiceTarget12;
uint8_t diceTargetWords = 12;
uint8_t diceLastRoll = 0;
int entropyLastY = -1;
bool fingerprintSelfTest = false;
bool hdSelfTest = false;
bool addressBip84SelfTest = false;
bool fingerprintValid = false;
char activeFingerprint[14] = "FPR: --------";
char vaultPassword[25] = {};
char vaultConfirmation[25] = {};
char vaultLabel[17] = {};
bool vaultConfirmPhase = false;
bool vaultMismatch = false;
uint32_t vaultRevealUntil = 0;
encrypted_seed_store::Result vaultResult = encrypted_seed_store::Result::crypto_error;
char vaultPath[64] = {};
char vaultFiles[6][64] = {};
uint8_t vaultFileCount = 0;
char txFiles[6][64] = {};
uint8_t txFileCount = 0;
uint8_t selectedVaultFile = 0;
bool vaultUnlockError = false;
uint8_t vaultFailCount = 0;      // S-6: intentos fallidos de desbloqueo
uint32_t vaultLockoutUntil = 0;  // bloqueo temporal (ms) tras N fallos
char activePassphrase[65] = {};
char passphraseEntry[65] = {};
char passphraseConfirmation[65] = {};
bool passphraseActive = false;
bool passphraseConfirmPhase = false;
bool passphraseMismatch = false;
bool passphraseReveal = false;
uint8_t passphraseKeyboardMode = 0;
bool vaultDeleteMode = false;
bool sessionDeleteMode = false;
bool deleteFailed = false;
bool pendingDeleteSession = false;
bool unlockConfirmIsSession = false;
char pendingDeletePath[64] = {};
enum class VaultFlow { individual, session_create, session_unlock, session_save_seed };
VaultFlow vaultFlow = VaultFlow::individual;
enum class NewSeedIntent { none, to_vault, ram_only };
NewSeedIntent newSeedIntent = NewSeedIntent::none;
bool sessionUnlocked = false;
uint8_t sessionMasterKey[32] = {};
uint8_t sessionVaultId[4] = {};
char sessionLabel[17] = {};
char sessionMetaPath[64] = {};
char sessionMetaFiles[6][64] = {};
uint8_t sessionMetaCount = 0;
char sessionSeedFiles[6][64] = {};
uint8_t sessionSeedCount = 0;
uint8_t selectedSessionFile = 0;
uint32_t lastUserActivity = 0;
constexpr uint32_t kSessionTimeoutWarnMs = 15000;
uint32_t lastWarnSecond = 0;
Screen sessionLockReturn = Screen::menu;
device_settings::Settings gSettings = device_settings::defaults();
Screen screensaverReturn = Screen::menu;
bool screensaverHardLock = false;
constexpr uint8_t kMaxLoadedSeeds = 6;
struct LoadedSeed {
  uint16_t indices[24];
  uint8_t count;
  char fingerprint[9];
  char label[17];
  bool used;
  bool inVault;
};
LoadedSeed loadedSeeds[kMaxLoadedSeeds] = {};
uint8_t loadedSeedCount = 0;
int8_t activeLoadedSeed = -1;
String activeAddress;
uint8_t addressChange = 0;
uint32_t addressIndex = 0;
char indexBuffer[7] = {};
char toastMessage[48] = {};
uint32_t toastUntil = 0;
QRCode addressQr;
QRCode wifiQr;
uint8_t wifiQrBuffer[256] = {};
uint8_t addressQrBuffer[256] = {};

struct PublicProfile {
  const char* title;
  const char* type;
  const char* path;
  uint32_t purpose;
  uint32_t version;
};
constexpr PublicProfile kPublicProfiles[] = {
    {"XPUB BIP44", "Legacy P2PKH", "m/44'/0'/0'", 44, 0x0488b21eUL},
    {"YPUB BIP49", "SegWit anidado P2SH", "m/49'/0'/0'", 49, 0x049d7cb2UL},
    {"ZPUB BIP84", "Native SegWit", "m/84'/0'/0'", 84, 0x04b24746UL},
};
constexpr uint8_t kPublicProfileCount = sizeof(kPublicProfiles) / sizeof(kPublicProfiles[0]);

void clearFingerprint() {
  fingerprintValid = false;
  memcpy(activeFingerprint, "FPR: --------", 14);
}

bool updateFingerprint() {
  clearFingerprint();
  if (!fingerprintSelfTest || wordCount != targetWords ||
      !bip39::checksum_valid(words, targetWords)) return false;
  uint8_t raw[4] = {};
  if (!bitcoin_fingerprint::calculate(words, targetWords, raw,
                                      passphraseActive ? activePassphrase : "")) return false;
  snprintf(activeFingerprint, sizeof(activeFingerprint), "FPR: %02X%02X%02X%02X",
           raw[0], raw[1], raw[2], raw[3]);
  memset(raw, 0, sizeof(raw));
  fingerprintValid = true;
  return true;
}

void clearDerivedData() {
  publicExtendedKey = ""; activeAddress = "";
  memset(publicKeyQrBuffer, 0, sizeof(publicKeyQrBuffer));
  memset(addressQrBuffer, 0, sizeof(addressQrBuffer));
  addressIndex = 0; addressChange = 0; publicKeyProfile = gSettings.defaultProfile;
}

void clearPassphrase() {
  encrypted_seed_store::wipe(activePassphrase, sizeof(activePassphrase));
  encrypted_seed_store::wipe(passphraseEntry, sizeof(passphraseEntry));
  encrypted_seed_store::wipe(passphraseConfirmation, sizeof(passphraseConfirmation));
  passphraseActive = false; passphraseConfirmPhase = false;
  passphraseMismatch = false; passphraseReveal = false;
}

int8_t findLoadedSeed(const char* fingerprint) {
  for (uint8_t i = 0; i < loadedSeedCount; ++i)
    if (loadedSeeds[i].used && !strcmp(loadedSeeds[i].fingerprint, fingerprint)) return i;
  return -1;
}

bool cacheCurrentSeed(const char* label = nullptr, bool markInVault = false) {
  if (!fingerprintValid) return false;
  uint8_t rawBase[4] = {}; char baseFingerprint[9] = {};
  if (!bitcoin_fingerprint::calculate(words, targetWords, rawBase, "")) return false;
  snprintf(baseFingerprint, sizeof(baseFingerprint), "%02X%02X%02X%02X",
           rawBase[0], rawBase[1], rawBase[2], rawBase[3]);
  encrypted_seed_store::wipe(rawBase, sizeof(rawBase));
  int8_t slot = activeLoadedSeed >= 0 ? activeLoadedSeed : findLoadedSeed(baseFingerprint);
  if (slot < 0) {
    if (loadedSeedCount >= kMaxLoadedSeeds) return false;
    slot = loadedSeedCount++;
  }
  LoadedSeed& item = loadedSeeds[slot];
  encrypted_seed_store::wipe(item.indices, sizeof(item.indices));
  memcpy(item.indices, words, targetWords * sizeof(uint16_t));
  item.count = targetWords;
  strncpy(item.fingerprint, baseFingerprint, sizeof(item.fingerprint) - 1);
  if (label && label[0]) strncpy(item.label, label, sizeof(item.label) - 1);
  else if (!item.label[0]) strncpy(item.label, "ACTIVA", sizeof(item.label) - 1);
  if (markInVault) item.inVault = true;
  item.used = true; activeLoadedSeed = slot;
  return true;
}

bool activateLoadedSeed(uint8_t slot) {
  if (slot >= loadedSeedCount || !loadedSeeds[slot].used) return false;
  Serial.printf("[SEED] activando slot %u (label=%s, enVault=%d)\n", slot,
                loadedSeeds[slot].fingerprint, loadedSeeds[slot].inVault);
  if (fingerprintValid) cacheCurrentSeed();
  const LoadedSeed& item = loadedSeeds[slot];
  encrypted_seed_store::wipe(words, sizeof(words));
  memcpy(words, item.indices, item.count * sizeof(uint16_t));
  targetWords = wordCount = item.count; prefix = ""; editingWord = -1;
  activeLoadedSeed = slot; clearDerivedData(); clearPassphrase();
  const bool ok = updateFingerprint();
  Serial.printf("[SEED] activo ahora: %s (passphraseActive=%d)\n",
                activeFingerprint, passphraseActive);
  return ok;
}

void textStyle(M5EPD_Canvas& canvas, uint8_t size = 2,
               uint8_t foreground = kBlack, uint8_t background = kWhite) {
  canvas.setTextColor(foreground, background);
  canvas.setTextSize(size);
  canvas.setTextDatum(TL_DATUM);
}

void centeredFit(M5EPD_Canvas& canvas, const char* text, int y,
                 int maxWidth = 500, uint8_t preferredSize = 2) {
  const char* t = lang::tr(text);
  uint8_t size = preferredSize;
  textStyle(canvas, size);
  while (size > 1 && canvas.textWidth(t) > maxWidth) {
    textStyle(canvas, --size);
  }
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString(t, kWidth / 2, y);
  canvas.setTextDatum(TL_DATUM);
}

void fingerprintBadge() {
  const char* value = !fingerprintSelfTest ? "ERROR" :
                      fingerprintValid ? activeFingerprint + 5 : "--------";
  textStyle(page, 3);
  page.setTextDatum(MR_DATUM);
  page.drawString(value, kWidth - 20, 46);
  textStyle(page, 2);          // restaurar tamaño (title() deja size 2)
  page.setTextDatum(TL_DATUM);
}

void title(const char* heading, const char* subtitle) {
  textStyle(page, 3);
  page.setCursor(20, 20);
  page.println(lang::tr(heading));
  textStyle(page, 2);
  page.setCursor(20, 88);
  page.println(lang::tr(subtitle));
  fingerprintBadge();
  page.drawFastHLine(20, 140, kWidth - 40, kBlack);
}

enum class Icon : uint8_t {
  none, key, lock, unlock, trash, eye, qr, plus, minus, save, folder, memory,
  back, forward, up, down, wrench, draw, dice, keyboard, reset, list, home,
  shield, x, check, wifi
};

void drawIcon(M5EPD_Canvas& canvas, Icon icon, int cx, int cy, uint8_t c) {
  switch (icon) {
    case Icon::key:
      canvas.fillCircle(cx - 4, cy, 6, c);
      canvas.fillRect(cx + 2, cy - 3, 10, 6, c);
      canvas.fillRect(cx + 9, cy - 6, 3, 3, c);
      canvas.fillRect(cx + 9, cy + 3, 3, 3, c);
      break;
    case Icon::lock:
      canvas.fillRoundRect(cx - 7, cy - 1, 14, 11, 3, c);
      canvas.drawRoundRect(cx - 4, cy - 11, 8, 8, 4, c);
      canvas.fillCircle(cx, cy + 3, 3, c);
      canvas.fillRect(cx - 1, cy + 6, 2, 4, c);
      break;
    case Icon::unlock:
      canvas.fillRoundRect(cx - 7, cy - 1, 14, 11, 3, c);
      canvas.drawLine(cx - 4, cy - 11, cx - 4, cy - 3, c);
      canvas.drawLine(cx - 4, cy - 11, cx + 1, cy - 11, c);
      canvas.fillCircle(cx, cy + 3, 3, c);
      canvas.fillRect(cx - 1, cy + 6, 2, 4, c);
      break;
    case Icon::trash:
      canvas.drawLine(cx - 10, cy - 8, cx + 10, cy - 8, c);
      canvas.fillRect(cx - 3, cy - 12, 6, 4, c);
      canvas.drawRoundRect(cx - 8, cy - 5, 16, 13, 3, c);
      canvas.drawLine(cx - 4, cy - 1, cx - 4, cy + 5, c);
      canvas.drawLine(cx, cy - 1, cx, cy + 5, c);
      canvas.drawLine(cx + 4, cy - 1, cx + 4, cy + 5, c);
      break;
    case Icon::eye:
      canvas.drawEllipse(cx, cy, 12, 7, c);
      canvas.fillCircle(cx, cy, 3, c);
      break;
    case Icon::qr:
      canvas.drawRoundRect(cx - 10, cy - 10, 8, 8, 2, c);
      canvas.fillRect(cx - 7, cy - 7, 3, 3, c);
      canvas.drawRoundRect(cx + 2, cy - 10, 8, 8, 2, c);
      canvas.fillRect(cx + 5, cy - 7, 3, 3, c);
      canvas.drawRoundRect(cx - 10, cy + 2, 8, 8, 2, c);
      canvas.fillRect(cx - 7, cy + 5, 3, 3, c);
      canvas.fillRect(cx + 3, cy + 4, 3, 3, c);
      canvas.fillRect(cx + 7, cy + 8, 3, 3, c);
      break;
    case Icon::plus:
      canvas.drawLine(cx - 7, cy, cx + 7, cy, c);
      canvas.drawLine(cx, cy - 7, cx, cy + 7, c);
      break;
    case Icon::minus:
      canvas.drawLine(cx - 7, cy, cx + 7, cy, c);
      break;
    case Icon::save:
      canvas.drawLine(cx, cy - 10, cx, cy + 2, c);
      canvas.drawLine(cx - 6, cy - 4, cx, cy + 2, c);
      canvas.drawLine(cx, cy + 2, cx + 6, cy - 4, c);
      canvas.drawLine(cx - 10, cy + 7, cx + 10, cy + 7, c);
      canvas.drawLine(cx - 10, cy + 7, cx - 10, cy + 10, c);
      canvas.drawLine(cx + 10, cy + 7, cx + 10, cy + 10, c);
      break;
    case Icon::folder:
      canvas.drawLine(cx - 12, cy - 6, cx - 3, cy - 6, c);
      canvas.drawLine(cx - 12, cy - 6, cx - 12, cy + 8, c);
      canvas.drawLine(cx - 12, cy + 8, cx + 12, cy + 8, c);
      canvas.drawLine(cx + 12, cy + 8, cx + 12, cy - 6, c);
      canvas.drawLine(cx - 3, cy - 6, cx + 1, cy - 12, c);
      canvas.drawLine(cx + 1, cy - 12, cx + 12, cy - 12, c);
      canvas.drawLine(cx + 12, cy - 12, cx + 12, cy - 6, c);
      break;
    case Icon::memory:
      canvas.drawRoundRect(cx - 11, cy - 9, 22, 18, 3, c);
      canvas.fillRect(cx - 7, cy - 4, 14, 8, c);
      canvas.fillRect(cx - 8, cy + 7, 4, 3, c);
      canvas.fillRect(cx - 1, cy + 7, 4, 3, c);
      canvas.fillRect(cx + 6, cy + 7, 4, 3, c);
      break;
    case Icon::back:
      canvas.drawLine(cx + 10, cy, cx - 10, cy, c);
      canvas.drawLine(cx - 10, cy, cx - 3, cy - 7, c);
      canvas.drawLine(cx - 10, cy, cx - 3, cy + 7, c);
      break;
    case Icon::forward:
      canvas.drawLine(cx - 10, cy, cx + 10, cy, c);
      canvas.drawLine(cx + 10, cy, cx + 3, cy - 7, c);
      canvas.drawLine(cx + 10, cy, cx + 3, cy + 7, c);
      break;
    case Icon::up:
      canvas.drawLine(cx, cy + 10, cx, cy - 7, c);
      canvas.drawLine(cx - 7, cy - 1, cx, cy - 7, c);
      canvas.drawLine(cx, cy - 7, cx + 7, cy - 1, c);
      break;
    case Icon::down:
      canvas.drawLine(cx, cy - 10, cx, cy + 7, c);
      canvas.drawLine(cx - 7, cy + 1, cx, cy + 7, c);
      canvas.drawLine(cx, cy + 7, cx + 7, cy + 1, c);
      break;
    case Icon::wrench:
      canvas.drawCircle(cx - 6, cy - 7, 6, c);
      canvas.drawLine(cx - 2, cy - 3, cx + 10, cy + 10, c);
      canvas.drawLine(cx - 1, cy - 2, cx + 10, cy + 9, c);
      break;
    case Icon::draw:
      canvas.fillTriangle(cx, cy - 12, cx + 7, cy + 7, cx - 7, cy + 7, c);
      break;
    case Icon::dice:
      canvas.drawRoundRect(cx - 8, cy - 8, 16, 16, 4, c);
      canvas.fillCircle(cx, cy, 2, c);
      canvas.fillCircle(cx - 4, cy - 4, 2, c);
      canvas.fillCircle(cx + 4, cy + 4, 2, c);
      canvas.fillCircle(cx - 4, cy + 4, 2, c);
      canvas.fillCircle(cx + 4, cy - 4, 2, c);
      break;
    case Icon::keyboard:
      canvas.fillRect(cx - 10, cy - 8, 6, 4, c);
      canvas.fillRect(cx - 3, cy - 8, 6, 4, c);
      canvas.fillRect(cx + 4, cy - 8, 6, 4, c);
      canvas.fillRect(cx - 10, cy - 1, 6, 4, c);
      canvas.fillRect(cx - 3, cy - 1, 6, 4, c);
      canvas.fillRect(cx + 4, cy - 1, 6, 4, c);
      canvas.fillRect(cx - 6, cy + 6, 13, 4, c);
      break;
    case Icon::reset:
      canvas.drawCircle(cx, cy, 7, c);
      canvas.fillTriangle(cx - 5, cy - 7, cx - 1, cy - 5, cx - 1, cy - 10, c);
      break;
    case Icon::list:
      canvas.fillRect(cx - 12, cy - 9, 3, 3, c);
      canvas.fillRect(cx - 12, cy - 2, 3, 3, c);
      canvas.fillRect(cx - 12, cy + 5, 3, 3, c);
      canvas.drawLine(cx - 8, cy - 8, cx + 9, cy - 8, c);
      canvas.drawLine(cx - 8, cy - 1, cx + 9, cy - 1, c);
      canvas.drawLine(cx - 8, cy + 6, cx + 9, cy + 6, c);
      break;
    case Icon::home:
      canvas.fillTriangle(cx, cy - 9, cx - 12, cy + 1, cx + 12, cy + 1, c);
      canvas.fillRect(cx - 8, cy + 1, 16, 9, c);
      break;
    case Icon::shield:
      canvas.fillTriangle(cx, cy - 12, cx - 10, cy - 4, cx - 10, cy + 4, c);
      canvas.fillTriangle(cx, cy - 12, cx + 10, cy - 4, cx + 10, cy + 4, c);
      canvas.fillRect(cx - 10, cy + 4, 20, 4, c);
      break;
    case Icon::x:
      canvas.drawLine(cx - 7, cy - 7, cx + 7, cy + 7, c);
      canvas.drawLine(cx - 7, cy + 7, cx + 7, cy - 7, c);
      break;
    case Icon::check:
      canvas.drawLine(cx - 8, cy - 1, cx - 2, cy + 6, c);
      canvas.drawLine(cx - 2, cy + 6, cx + 9, cy - 6, c);
      break;
    case Icon::wifi:
      canvas.fillCircle(cx, cy + 7, 3, c);
      canvas.drawLine(cx - 9, cy - 1, cx, cy - 9, c);
      canvas.drawLine(cx, cy - 9, cx + 9, cy - 1, c);
      canvas.drawLine(cx - 4, cy - 1, cx, cy - 5, c);
      canvas.drawLine(cx, cy - 5, cx + 4, cy - 1, c);
      break;
    case Icon::none: break;
  }
}

void buttonOn(M5EPD_Canvas& canvas, const Rect& r, const char* label,
              bool enabled = true, bool selected = false,
              Icon icon = Icon::none) {
  const char* l = lang::tr(label);
  const uint8_t background = selected && enabled ? kBlack : kWhite;
  const uint8_t foreground = selected && enabled ? kWhite : kBlack;
  canvas.fillRoundRect(r.x, r.y, r.w, r.h, 10, background);
  canvas.drawRoundRect(r.x, r.y, r.w, r.h, 10, foreground);
  canvas.setTextColor(foreground, background);
  canvas.setTextSize(2);
  const int textLimit = icon == Icon::none ? r.w - 24 : r.w - 68;
  if (canvas.textWidth(l) > textLimit) canvas.setTextSize(1);
  canvas.setTextDatum(MC_DATUM);
  if (icon == Icon::none) {
    canvas.drawString(l, r.x + r.w / 2, r.y + r.h / 2);
  } else {
    drawIcon(canvas, icon, r.x + 30, r.y + r.h / 2, foreground);
    canvas.drawString(l, r.x + 30 + (r.w - 52) / 2, r.y + r.h / 2);
  }
  if (!enabled) {
    canvas.drawLine(r.x + 12, r.y + r.h / 2, r.x + r.w - 12,
                    r.y + r.h / 2, kBlack);
  }
}

void updateButton(const Rect& rect, const char* label, bool enabled,
                  bool selected, Icon icon = Icon::none,
                  m5epd_update_mode_t mode = UPDATE_MODE_A2) {
  M5EPD_Canvas region(&M5.EPD);
  if (region.createCanvas(rect.w, rect.h) == nullptr) return;
  buttonOn(region, Rect{0, 0, rect.w, rect.h}, label, enabled, selected, icon);
  region.pushCanvas(rect.x, rect.y, mode);
  region.deleteCanvas();
}

void fullRefresh(m5epd_update_mode_t mode = UPDATE_MODE_GL16) {
  page.pushCanvas(0, 0, mode);
}

uint8_t progressPercent = 255;

void drawProgressBar(int y, uint8_t percent) {
  M5EPD_Canvas bar(&M5.EPD);
  if (bar.createCanvas(500, 34)) {
    bar.fillCanvas(kWhite);
    bar.drawRoundRect(0, 0, 500, 34, 8, kBlack);
    const int w = (percent * 496) / 100;
    if (w > 4) bar.fillRoundRect(2, 2, w - 4, 30, 6, kBlack);
    bar.pushCanvas(20, y, UPDATE_MODE_A2);
    bar.deleteCanvas();
  }
}

void storeProgress(uint32_t done, uint32_t total) {
  const uint8_t pct = total ? static_cast<uint8_t>(
      (static_cast<uint64_t>(done) * 100) / total) : 100;
  if (pct != progressPercent) {
    progressPercent = pct;
    drawProgressBar(340, pct);
  }
}

void showToast(const char* msg) {
  strncpy(toastMessage, lang::tr(msg), sizeof(toastMessage) - 1);
  toastMessage[sizeof(toastMessage) - 1] = '\0';
  toastUntil = millis() + 1600;
  M5EPD_Canvas t(&M5.EPD);
  if (t.createCanvas(500, 50)) {
    t.fillCanvas(kBlack);
    t.setTextColor(kWhite, kBlack);
    t.setTextSize(2);
    t.setTextDatum(MC_DATUM);
    t.drawString(toastMessage, 250, 25);
    t.setTextDatum(TL_DATUM);
    t.pushCanvas(20, 15, UPDATE_MODE_A2);
    t.deleteCanvas();
  }
}

void blankPage() {
  page.fillCanvas(kWhite);
  page.drawFastHLine(20, 930, kWidth - 40, kBlack);
  textStyle(page, 1);
  page.setTextDatum(BL_DATUM);
  page.drawString(String("Firmware: ") + kVersion, 20, 954);
  page.setTextDatum(BR_DATUM);
  page.drawString(lang::tr("NO USAR FONDOS REALES (DEV)"), 520, 954);
  page.setTextDatum(TL_DATUM);
  textStyle(page);
}

const char* menuLabel(uint8_t index) {
  return (index == 0 && fingerprintValid) ? "SEMILLA ACTIVA" : kMenuLabels[index];
}

bool menuEnabled(uint8_t index) {
  if (index == 1) return !fingerprintValid;  // GENERAR ENTROPIA
  return true;
}

const char* menuHint(uint8_t index) {
  switch (index) {
    case 0: return fingerprintValid ? "Abre el menu de la semilla que ya esta activa"
                                    : "Escribe una semilla BIP39 palabra a palabra";
    case 1: return fingerprintValid ? "Descarta la semilla activa para crear otra"
                                    : "Genera una semilla aleatoria con entropia propia";
    case 2: return "Cifra y guarda varias semillas bajo una contrasena maestra";
    case 3: return fingerprintValid ? "Recibe un PSBT o una semilla por WiFi desde tu movil"
                                    : "Recibe una semilla BIP39 por texto desde tu movil";
    case 4: return "Transacciones guardadas para revisar o volver a firmar";
    case 5: return "Idioma, bloqueo, derivacion y estado de la radio";
    default: return "Bloquea el dispositivo y muestra la portada";
  }
}

const char* activeHint(uint8_t index) {
  switch (index) {
    case 0: return "Deriva la clave publica (xpub/zpub) para ver solo direcciones";
    case 1: return "Copia y comprueba la semilla (palabras, QR o SEEDQR)";
    case 2: return "Anade una passphrase BIP39 (cambia todas las direcciones)";
    case 3: return "Deriva direcciones concretas para recibir o para cambio";
    case 4: return sessionUnlocked ? "Gestiona las semillas del vault de sesion"
                                    : "Borra la semilla de la memoria RAM";
    case 5: return "Recibe un PSBT o archivo por WiFi para firmar";
    case 6: return sessionUnlocked ? "Cierra el vault y borra la clave maestra de RAM"
                                   : "Ajustes del dispositivo";
    case 7: return sessionUnlocked ? "Ajustes del dispositivo" : "Vuelve al menu general";
    default: return "Vuelve al menu general";
  }
}

void drawMenu() {
  blankPage();
  title("SEED WORKSTATION",
        fingerprintValid ? "Semilla activa en memoria" : "Sin semilla cargada");
  static const Icon kMenuIcons[] = {Icon::keyboard, Icon::draw, Icon::lock,
                                    Icon::wifi, Icon::list, Icon::wrench, Icon::lock};
  for (uint8_t i = 0; i < 7; ++i) {
    buttonOn(page, kMenu[i], menuLabel(i), menuEnabled(i), focusIndex == i, kMenuIcons[i]);
  }
  textStyle(page, 1); page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr(menuHint(focusIndex)), 270, 670);
  // Icono de ayuda (opcion secundaria, abajo a la derecha).
  page.fillCircle(kHelpIcon.x + 32, kHelpIcon.y + 32, 30, kBlack);
  textStyle(page, 3, kWhite, kBlack);
  page.setTextDatum(MC_DATUM);
  page.drawString("?", kHelpIcon.x + 32, kHelpIcon.y + 32);
  page.setTextDatum(TL_DATUM);
  fullRefresh();
}

void resetPhrase(uint8_t count) {
  targetWords = count;
  wordCount = 0;
  prefix = "";
  editingWord = -1;
  activeLoadedSeed = -1;
  clearFingerprint();
  publicExtendedKey = "";
  memset(publicKeyQrBuffer, 0, sizeof(publicKeyQrBuffer));
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
  for (auto& word : words) word = bip39::kInvalidWord;
}

void drawLength() {
  blankPage();
  title("LONGITUD", "Elige el numero de palabras");
  buttonOn(page, kChoose12, "12 PALABRAS", true, focusIndex == 0, Icon::list);
  buttonOn(page, kChoose24, "24 PALABRAS", true, focusIndex == 1, Icon::list);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 2);
  fullRefresh();
}

void drawEntropyLength() {
  blankPage();
  title("NUEVA SEMILLA", "Elige la longitud BIP39");
  buttonOn(page, kChoose12, "12 PALABRAS", true, focusIndex == 0, Icon::list);
  buttonOn(page, kChoose24, "24 PALABRAS", true, focusIndex == 1, Icon::list);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 2);
  buttonOn(page, kAction, "TIRAR DADOS", true, focusIndex == 3, Icon::dice);
  fullRefresh();
}

void initEntropy() {
  if (entropySourceActive) bootloader_random_disable();
  bootloader_random_enable();
  entropySourceActive = true;
  entropyHealthOk = true;
  entropyLastRandom = 0;
  uint8_t initialMaterial[64] = {};
  esp_fill_random(initialMaterial, sizeof(initialMaterial));
  uint8_t initialInput[96] = {};
  memcpy(initialInput, "M5PAPER-ENTROPY-V2-INIT", 23);
  memcpy(initialInput + 32, initialMaterial, sizeof(initialMaterial));
  mbedtls_sha256_ret(initialInput, sizeof(initialInput), entropyState, 0);
  encrypted_seed_store::wipe(initialMaterial, sizeof(initialMaterial));
  encrypted_seed_store::wipe(initialInput, sizeof(initialInput));
  entropySamples = 0;
  entropyLastX = entropyLastY = -1;
  if (!entropyCanvasReady) {
    entropyCanvasReady = entropyCanvas.createCanvas(kEntropyArea.w,
                                                    kEntropyArea.h) != nullptr;
  }
  if (entropyCanvasReady) {
    entropyCanvas.fillCanvas(kWhite);
    entropyCanvas.drawRect(0, 0, kEntropyArea.w, kEntropyArea.h, kBlack);
  }
}

void renderEntropyProgress(bool updateCreate = false) {
  M5EPD_Canvas progress(&M5.EPD);
  if (progress.createCanvas(500, 40)) {
    progress.fillCanvas(kWhite);
    textStyle(progress, 2);
    progress.setCursor(0, 4);
    progress.printf("Mezcla: %u/%u | RNG: %s", entropySamples, kEntropyTarget,
                    entropyHealthOk ? "FISICO" : "ERROR");
    progress.pushCanvas(20, 140, UPDATE_MODE_DU4);
    progress.deleteCanvas();
  }
  if (updateCreate) {
    updateButton(kEntropyCreate, "CREAR SEMILLA",
                 entropySamples >= kEntropyTarget && entropyHealthOk,
                 focusIndex == 1, Icon::draw,
                 UPDATE_MODE_DU4);
  }
}

void drawEntropy() {
  blankPage();
  title("DIBUJA ENTROPIA", "Traza movimientos largos e irregulares");
  textStyle(page, 2);
  page.setCursor(20, 145);
  page.printf(lang::tr("Mezcla: %u/%u | RNG: %s"), entropySamples, kEntropyTarget,
              entropyHealthOk ? "FISICO" : "ERROR");
  if (entropyCanvasReady) entropyCanvas.pushToCanvas(kEntropyArea.x,
                                                     kEntropyArea.y, &page);
  buttonOn(page, kEntropyReset, "REINICIAR", true, false, Icon::reset);
  buttonOn(page, kEntropyCreate, "CREAR SEMILLA",
           entropySamples >= kEntropyTarget && entropyHealthOk, focusIndex == 1,
           Icon::draw);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
  fullRefresh();
}

void entropyTouch(int screenX, int screenY) {
  if (!kEntropyArea.contains(screenX, screenY) || !entropyCanvasReady ||
      entropySamples >= kEntropyTarget) return;
  const int x = screenX - kEntropyArea.x;
  const int y = screenY - kEntropyArea.y;
  uint8_t material[96] = {};
  memcpy(material, entropyState, 32);
  memcpy(material + 32, "M5PAPER-ENTROPY-V2-SAMPLE", 25);
  const uint32_t values[4] = {entropySamples, static_cast<uint32_t>(x),
                              static_cast<uint32_t>(y), micros()};
  memcpy(material + 60, values, sizeof(values));
  uint32_t randomWords[5] = {};
  for (uint8_t i = 0; i < 5; ++i) {
    randomWords[i] = esp_random();
    if (entropyLastRandom && randomWords[i] == entropyLastRandom) entropyHealthOk = false;
    entropyLastRandom = randomWords[i];
  }
  memcpy(material + 76, randomWords, sizeof(randomWords));
  mbedtls_sha256_ret(material, sizeof(material), entropyState, 0);
  encrypted_seed_store::wipe(material, sizeof(material));
  encrypted_seed_store::wipe(randomWords, sizeof(randomWords));
  ++entropySamples;
  if (entropyLastX >= 0)
    entropyCanvas.drawLine(entropyLastX, entropyLastY, x, y, 3, kBlack);
  else
    entropyCanvas.fillCircle(x, y, 3, kBlack);
  entropyLastX = x;
  entropyLastY = y;
  if ((entropySamples % 8) == 0 || entropySamples == kEntropyTarget) {
    entropyCanvas.pushCanvas(kEntropyArea.x, kEntropyArea.y, UPDATE_MODE_DU4);
    renderEntropyProgress(entropySamples == kEntropyTarget);
  }
}

void drawReview();

void finishEntropy() {
  if (entropySamples < kEntropyTarget || !entropyHealthOk || !entropySourceActive) return;
  uint8_t finalRandom[64] = {}, finalInput[128] = {}, finalEntropy[32] = {};
  esp_fill_random(finalRandom, sizeof(finalRandom));
  memcpy(finalInput, entropyState, sizeof(entropyState));
  memcpy(finalInput + 32, "M5PAPER-ENTROPY-V2-FINAL", 24);
  memcpy(finalInput + 64, finalRandom, sizeof(finalRandom));
  mbedtls_sha256_ret(finalInput, sizeof(finalInput), finalEntropy, 0);
  bootloader_random_disable();
  entropySourceActive = false;
  const size_t bytes = targetWords == 12 ? 16 : 32;
  if (!bip39::from_entropy(finalEntropy, bytes, words, targetWords)) {
    encrypted_seed_store::wipe(finalRandom, sizeof(finalRandom));
    encrypted_seed_store::wipe(finalInput, sizeof(finalInput));
    encrypted_seed_store::wipe(finalEntropy, sizeof(finalEntropy));
    return;
  }
  wordCount = targetWords;
  prefix = "";
  updateFingerprint();
  encrypted_seed_store::wipe(entropyState, sizeof(entropyState));
  encrypted_seed_store::wipe(finalRandom, sizeof(finalRandom));
  encrypted_seed_store::wipe(finalInput, sizeof(finalInput));
  encrypted_seed_store::wipe(finalEntropy, sizeof(finalEntropy));
  requestSecurity(Screen::review,
                  newSeedIntent != NewSeedIntent::none
                      ? Screen::session_seed_list : Screen::menu);
}

void initDice() {
  encrypted_seed_store::wipe(diceState, sizeof(diceState));
  diceRolls = 0;
  diceLastRoll = 0;
  diceTarget = diceTargetWords == 24 ? kDiceTarget24 : kDiceTarget12;
}

void renderDiceDynamic() {
  M5EPD_Canvas progress(&M5.EPD);
  if (progress.createCanvas(500, 36)) {
    progress.fillCanvas(kWhite);
    textStyle(progress, 2);
    progress.setTextDatum(MC_DATUM);
    progress.drawString(String("Lanzamientos: ") + diceRolls + "/" + diceTarget +
                        (diceLastRoll ? String("   Ultimo: ") + diceLastRoll : ""),
                        250, 18);
    progress.setTextDatum(TL_DATUM);
    progress.pushCanvas(20, 270, UPDATE_MODE_A2);
    progress.deleteCanvas();
  }
  updateButton(kAction, "CREAR SEMILLA", diceRolls >= diceTarget,
               focusIndex == 2, Icon::check, UPDATE_MODE_A2);
}

void registerDiceRoll(uint8_t value) {
  if (diceRolls >= diceTarget) return;
  uint8_t material[96] = {};
  memcpy(material, diceState, 32);
  memcpy(material + 32, "M5PAPER-DICE-V1-SAMPLE", 22);
  const uint32_t values[4] = {diceRolls, value, millis(), micros()};
  memcpy(material + 60, values, sizeof(values));
  uint32_t randomWords[5] = {};
  for (uint8_t i = 0; i < 5; ++i) randomWords[i] = esp_random();
  memcpy(material + 76, randomWords, sizeof(randomWords));
  mbedtls_sha256_ret(material, sizeof(material), diceState, 0);
  encrypted_seed_store::wipe(material, sizeof(material));
  encrypted_seed_store::wipe(randomWords, sizeof(randomWords));
  ++diceRolls;
  diceLastRoll = value;
  renderDiceDynamic();
}

void finishDice() {
  if (diceRolls < diceTarget) return;
  uint8_t finalRandom[64] = {}, finalInput[128] = {}, finalEntropy[32] = {};
  esp_fill_random(finalRandom, sizeof(finalRandom));
  memcpy(finalInput, diceState, sizeof(diceState));
  memcpy(finalInput + 32, "M5PAPER-DICE-V1-FINAL", 22);
  memcpy(finalInput + 64, finalRandom, sizeof(finalRandom));
  mbedtls_sha256_ret(finalInput, sizeof(finalInput), finalEntropy, 0);
  const size_t bytes = diceTargetWords == 12 ? 16 : 32;
  if (!bip39::from_entropy(finalEntropy, bytes, words, diceTargetWords)) {
    encrypted_seed_store::wipe(finalRandom, sizeof(finalRandom));
    encrypted_seed_store::wipe(finalInput, sizeof(finalInput));
    encrypted_seed_store::wipe(finalEntropy, sizeof(finalEntropy));
    return;
  }
  targetWords = diceTargetWords;
  wordCount = targetWords;
  prefix = "";
  updateFingerprint();
  encrypted_seed_store::wipe(diceState, sizeof(diceState));
  encrypted_seed_store::wipe(finalRandom, sizeof(finalRandom));
  encrypted_seed_store::wipe(finalInput, sizeof(finalInput));
  encrypted_seed_store::wipe(finalEntropy, sizeof(finalEntropy));
  requestSecurity(Screen::review,
                  newSeedIntent != NewSeedIntent::none
                      ? Screen::session_seed_list : Screen::menu);
}

void drawDice() {
  blankPage();
  title("TIRAR DADOS", "Entropia con dados fisicos 1-6");
  buttonOn(page, kDiceLength12, "12 PALABRAS", true, diceTargetWords == 12, Icon::list);
  buttonOn(page, kDiceLength24, "24 PALABRAS", true, diceTargetWords == 24, Icon::list);
  textStyle(page, 2);
  page.setTextDatum(MC_DATUM);
  page.drawString(String(lang::tr("Lanzamientos: ")) + diceRolls + "/" + diceTarget +
                  (diceLastRoll ? String(lang::tr("   Ultimo: ")) + diceLastRoll : ""),
                  270, 288);
  page.drawString(lang::tr("Toca la cara del dado que ha salido"), 270, 320);
  page.setTextDatum(TL_DATUM);
  for (uint8_t i = 0; i < 6; ++i) {
    buttonOn(page, kDiceValue[i], String(i + 1).c_str(), true, false, Icon::dice);
  }
  buttonOn(page, kDiceReset, "REINICIAR", true, focusIndex == 0, Icon::reset);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 1);
  buttonOn(page, kAction, "CREAR SEMILLA", diceRolls >= diceTarget,
           focusIndex == 2, Icon::check);
  fullRefresh();
}

char keyAt(int x, int y) {
  for (const auto& row : kRows) {
    if (y < row.y || y >= row.y + 64 || x < row.x) continue;
    const int index = (x - row.x) / row.width;
    if (index >= 0 && index < static_cast<int>(strlen(row.letters)))
      return static_cast<char>(tolower(row.letters[index]));
  }
  return '\0';
}

void drawKeyboardKeys() {
  for (const auto& row : kRows) {
    for (size_t i = 0; row.letters[i]; ++i) {
      const Rect key{row.x + static_cast<int>(i) * row.width, row.y,
                     row.width - 4, 64};
      char label[] = {row.letters[i], '\0'};
      buttonOn(page, key, label);
    }
  }
  buttonOn(page, kDelete, "BORRAR", true, false, Icon::back);
  buttonOn(page, kAdd, "ANADIR", true, false, Icon::plus);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
  buttonOn(page, kAction, "REVISAR", true, focusIndex == 1, Icon::check);
}

void renderWordRegion(M5EPD_Canvas& region) {
  region.fillCanvas(kWhite);
  textStyle(region, 2);
  region.setCursor(5, 5);
  if (editingWord >= 0)
    region.printf("Sustituir palabra %u de %u", editingWord + 1, targetWords);
  else
    region.printf("Palabra %u de %u", wordCount + 1, targetWords);
  region.drawRoundRect(5, 55, 500, 58, 8, kBlack);
  textStyle(region, 3);
  region.setCursor(19, 58);
  region.print(prefix.length() ? prefix : "_");
}

size_t currentSuggestions(uint16_t* matches) {
  return bip39::find_matches(prefix, matches, 4);
}

void renderSuggestions(M5EPD_Canvas& region) {
  region.fillCanvas(kWhite);
  textStyle(region, 2);
  uint16_t matches[4] = {};
  const size_t count = currentSuggestions(matches);
  region.setCursor(5, 2);
  region.printf("Coincidencias: %u", static_cast<unsigned>(count));
  for (uint8_t i = 0; i < 4; ++i) {
    Rect local{kSuggestion[i].x - 15, kSuggestion[i].y - 590,
               kSuggestion[i].w, kSuggestion[i].h};
    if (i < min(count, static_cast<size_t>(4)))
      buttonOn(region, local, bip39::word_at(matches[i]));
  }
}

void updateKeyboardDynamic() {
  M5EPD_Canvas wordRegion(&M5.EPD);
  if (wordRegion.createCanvas(510, 120)) {
    renderWordRegion(wordRegion);
    wordRegion.pushCanvas(15, 140, UPDATE_MODE_DU4);
    wordRegion.deleteCanvas();
  }
  M5EPD_Canvas suggestions(&M5.EPD);
  if (suggestions.createCanvas(510, 190)) {
    renderSuggestions(suggestions);
    suggestions.pushCanvas(15, 590, UPDATE_MODE_DU4);
    suggestions.deleteCanvas();
  }
}

void drawKeyboard() {
  blankPage();
  title("TECLADO BIP39", "Escribe 4 letras y toca la palabra");
  drawKeyboardKeys();
  M5EPD_Canvas wordRegion(&M5.EPD);
  wordRegion.createCanvas(510, 120);
  renderWordRegion(wordRegion);
  wordRegion.pushToCanvas(15, 140, &page);
  wordRegion.deleteCanvas();
  M5EPD_Canvas suggestions(&M5.EPD);
  suggestions.createCanvas(510, 190);
  renderSuggestions(suggestions);
  suggestions.pushToCanvas(15, 590, &page);
  suggestions.deleteCanvas();
  fullRefresh();
}

const char* passphraseRows(uint8_t row) {
  static const char* lower[] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
  static const char* upper[] = {"QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"};
  static const char* symbols[] = {"1234567890", "!@#$%&*()", "-_=+[]{}?"};
  static const char* extra[] = {"`~^\\|/<>", ";:'\",.", ""};
  return passphraseKeyboardMode == 0 ? lower[row] :
         passphraseKeyboardMode == 1 ? upper[row] :
         passphraseKeyboardMode == 2 ? symbols[row] : extra[row];
}

char passphraseKeyAt(int x, int y) {
  for (uint8_t r = 0; r < 3; ++r) {
    const char* keys = passphraseRows(r); const int width = r == 2 ? 60 : 52;
    const int start = r == 0 ? 10 : r == 1 ? 34 : 60;
    const int top = 265 + r * 80;
    if (y < top || y >= top + 64 || x < start) continue;
    const int index = (x - start) / width;
    if (index >= 0 && index < static_cast<int>(strlen(keys))) return keys[index];
  }
  return '\0';
}

void drawPassphraseKeys() {
  for (uint8_t r = 0; r < 3; ++r) {
    const char* keys = passphraseRows(r); const int width = r == 2 ? 60 : 52;
    const int start = r == 0 ? 10 : r == 1 ? 34 : 60;
    const int top = 265 + r * 80;
    for (size_t i = 0; keys[i]; ++i) {
      char label[2] = {keys[i], '\0'};
      buttonOn(page, Rect{start + static_cast<int>(i) * width, top, width - 4, 64}, label);
    }
  }
}

char* currentPassphraseEntry() {
  return passphraseConfirmPhase ? passphraseConfirmation : passphraseEntry;
}

void drawPassphraseInput() {
  blankPage();
  title("BIP39 PASSPHRASE", passphraseConfirmPhase ? "Repite EXACTAMENTE: mayusculas incluidas" :
        "Las mayusculas importan (ASCII)");
  char* value = currentPassphraseEntry(); const size_t length = strlen(value);
  textStyle(page, 2); page.setCursor(20, 150);
  page.println(passphraseMismatch ? lang::tr("NO COINCIDEN. REPITE LA CONFIRMACION.") :
               passphraseActive ? lang::tr("Hay una passphrase activa en RAM.") :
               lang::tr("No se guardara. 'Casa' y 'casa' son distintas."));
  page.drawRoundRect(20, 195, 500, 52, 8, kBlack); page.setCursor(35, 204);
  if (passphraseReveal) page.print(value);
  else for (size_t i = 0; i < length; ++i) page.print('*');
  drawPassphraseKeys();
  buttonOn(page, kDelete, "BORRAR", length > 0, false, Icon::x);
  buttonOn(page, kAdd, passphraseConfirmPhase ? "ACTIVAR" : "CONTINUAR",
           length > 0, false, Icon::key);
  buttonOn(page, kPassMode, passphraseKeyboardMode == 0 ? "abc" :
           passphraseKeyboardMode == 1 ? "ABC" :
           passphraseKeyboardMode == 2 ? "123 / SIMB" : "SIMB 2");
  buttonOn(page, kPassSpace, "ESPACIO");
  buttonOn(page, kPassReveal, passphraseReveal ? "OCULTAR" : "MOSTRAR",
           length > 0, false, Icon::eye);
  if (passphraseActive) buttonOn(page, kPassRemove, "QUITAR PASSPHRASE", true,
                                 false, Icon::trash);
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, passphraseConfirmPhase ? "ACTIVAR" : "CONTINUAR",
           length > 0, focusIndex == 1, Icon::key);
  fullRefresh();
}

void beginPassphrase() {
  encrypted_seed_store::wipe(passphraseEntry, sizeof(passphraseEntry));
  encrypted_seed_store::wipe(passphraseConfirmation, sizeof(passphraseConfirmation));
  passphraseConfirmPhase = false; passphraseMismatch = false;
  passphraseReveal = false; passphraseKeyboardMode = 0;
  screen = Screen::passphrase_input; focusIndex = 0; drawPassphraseInput();
}

void warningIcon(M5EPD_Canvas& canvas, int cx, int top);
void discardActiveSeed();
void drawActiveSeed();

char* activeVaultPassword() {
  return vaultConfirmPhase ? vaultConfirmation : vaultPassword;
}

void drawVaultLabel() {
  blankPage();
  const bool sessionSeed = vaultFlow == VaultFlow::session_save_seed;
  const bool sessionCreate = vaultFlow == VaultFlow::session_create;
  title(sessionSeed ? "ETIQUETA SEMILLA" : sessionCreate ? "NUEVO VAULT" : "ETIQUETA VAULT",
        sessionSeed ? "Nombre reconocible dentro del Vault" :
        sessionCreate ? "Nombre del Vault de sesion" : "Nombre reconocible para la copia cifrada");
  textStyle(page, 2); page.setCursor(20, 155);
  page.println(lang::tr("1-16 letras. Ejemplos:"));
  page.setCursor(20, 180); page.println(lang::tr("ahorro, viajes o casa"));
  page.drawRoundRect(20, 205, 500, 52, 8, kBlack);
  page.setCursor(35, 214); page.print(vaultLabel[0] ? vaultLabel : "_");
  drawKeyboardKeys();
  buttonOn(page, kDelete, "BORRAR", true, false, Icon::back);
  buttonOn(page, kAdd, "CONTINUAR", vaultLabel[0], false, Icon::check);
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, "CONTINUAR", vaultLabel[0], focusIndex == 1, Icon::check);
  textStyle(page, 1); page.setTextDatum(MC_DATUM);
  String preview = sessionSeed ? String(activeFingerprint + 5) + "-" +
      (vaultLabel[0] ? vaultLabel : "label") + ".svs" :
      sessionCreate ? String("SESSION-") + (vaultLabel[0] ? vaultLabel : "label") + ".svm" :
      String(activeFingerprint + 5) + "-" + (vaultLabel[0] ? vaultLabel : "label") + ".vlt";
  page.drawString(preview, 270, 650); page.setTextDatum(TL_DATUM);
  fullRefresh();
}

void updateVaultLabelDynamic(bool updateActions = false) {
  M5EPD_Canvas field(&M5.EPD);
  if (field.createCanvas(500, 52)) {
    field.fillCanvas(kWhite); field.drawRoundRect(0, 0, 500, 52, 8, kBlack);
    textStyle(field, 2); field.setCursor(15, 9);
    field.print(vaultLabel[0] ? vaultLabel : "_");
    field.pushCanvas(20, 205, UPDATE_MODE_A2); field.deleteCanvas();
  }
  M5EPD_Canvas preview(&M5.EPD);
  if (preview.createCanvas(500, 40)) {
    preview.fillCanvas(kWhite); textStyle(preview, 1); preview.setTextDatum(MC_DATUM);
    String name = vaultFlow == VaultFlow::session_save_seed ?
        String(activeFingerprint + 5) + "-" + (vaultLabel[0] ? vaultLabel : "label") + ".svs" :
        vaultFlow == VaultFlow::session_create ? String("SESSION-") +
        (vaultLabel[0] ? vaultLabel : "label") + ".svm" : String(activeFingerprint + 5) + "-" +
        (vaultLabel[0] ? vaultLabel : "label") + ".vlt";
    preview.drawString(name, 250, 20); preview.pushCanvas(20, 630, UPDATE_MODE_A2);
    preview.deleteCanvas();
  }
  if (updateActions) {
    updateButton(kAdd, "CONTINUAR", vaultLabel[0], false, Icon::check, UPDATE_MODE_A2);
    updateButton(kAction, "CONTINUAR", vaultLabel[0], focusIndex == 1, Icon::check, UPDATE_MODE_A2);
  }
}

void drawVaultPassword() {
  blankPage();
  title("VAULT SEGURO", vaultConfirmPhase ? "Repite la contrasena" : "Crea una contrasena para la SD");
  char* value = activeVaultPassword();
  const size_t length = strlen(value);
  textStyle(page, 2);
  page.setCursor(20, 155);
  page.println(vaultMismatch ? lang::tr("NO COINCIDEN: repite la segunda contrasena.")
                             : lang::tr("Minimo 12 letras. No podremos recuperarla."));
  page.drawRoundRect(20, 205, 500, 52, 8, kBlack);
  page.setCursor(35, 214);
  const bool revealed = vaultRevealUntil &&
      static_cast<int32_t>(vaultRevealUntil - millis()) > 0;
  if (revealed) page.print(value);
  else for (size_t i = 0; i < length; ++i) page.print('*');
  drawKeyboardKeys();
  buttonOn(page, kDelete, "BORRAR", true, false, Icon::back);
  buttonOn(page, kAdd, vaultConfirmPhase ? "GUARDAR CIFRADO" : "CONTINUAR",
           length >= 12, false, vaultConfirmPhase ? Icon::lock : Icon::check);
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, vaultConfirmPhase ? "GUARDAR" : "CONTINUAR",
           length >= 12, focusIndex == 1, vaultConfirmPhase ? Icon::lock : Icon::check);
  buttonOn(page, kVaultReveal, revealed ? "VISIBLE 3 SEG." : "MOSTRAR 3 SEG.",
           length > 0, revealed, Icon::eye);
  fullRefresh();
}

void updateVaultPasswordDynamic(bool updateActions = false) {
  char* value = activeVaultPassword();
  const size_t length = strlen(value);
  M5EPD_Canvas field(&M5.EPD);
  if (field.createCanvas(500, 52)) {
    field.fillCanvas(kWhite); field.drawRoundRect(0, 0, 500, 52, 8, kBlack);
    textStyle(field, 2); field.setCursor(15, 9);
    const bool revealed = vaultRevealUntil &&
        static_cast<int32_t>(vaultRevealUntil - millis()) > 0;
    if (revealed) field.print(value);
    else for (size_t i = 0; i < length; ++i) field.print('*');
    field.pushCanvas(20, 205, UPDATE_MODE_A2); field.deleteCanvas();
  }
  if (updateActions) {
    const bool unlocking = screen == Screen::vault_unlock;
    const char* addLabel = unlocking ? "DESBLOQUEAR" :
                           vaultConfirmPhase ? "GUARDAR CIFRADO" : "CONTINUAR";
    const char* actionLabel = unlocking ? "DESBLOQUEAR" :
                              vaultConfirmPhase ? "GUARDAR" : "CONTINUAR";
    const bool enabled = unlocking ? length >= 1 : length >= 12;
    const Icon addIcon = unlocking ? Icon::unlock :
                         vaultConfirmPhase ? Icon::lock : Icon::check;
    updateButton(kAdd, addLabel, enabled, false, addIcon, UPDATE_MODE_A2);
    updateButton(kAction, actionLabel, enabled, focusIndex == 1, addIcon, UPDATE_MODE_A2);
  }
}

const char* vaultResultText(encrypted_seed_store::Result result) {
  switch (result) {
    case encrypted_seed_store::Result::ok: return "VAULT GUARDADO Y VERIFICADO";
    case encrypted_seed_store::Result::no_sd: return "NO SE DETECTA LA TARJETA SD";
    case encrypted_seed_store::Result::exists: return "YA EXISTE UN VAULT PARA ESTA SEED";
    case encrypted_seed_store::Result::wrong_password_or_tampered: return "FALLO DE VERIFICACION";
    case encrypted_seed_store::Result::io_error: return "ERROR DE ESCRITURA EN LA SD";
    default: return "ERROR CRIPTOGRAFICO";
  }
}

void drawVaultResult() {
  blankPage();
  const bool sessionRecord = vaultFlow == VaultFlow::session_save_seed;
  title(sessionRecord ? "VAULT DE SESION" : "VAULT SEGURO",
        vaultResult == encrypted_seed_store::Result::ok ? "Copia cifrada terminada" : "Operacion no completada");
  uint8_t resultSize = 3; textStyle(page, resultSize);
  while (resultSize > 1 && page.textWidth(vaultResultText(vaultResult)) > 500) {
    --resultSize; textStyle(page, resultSize);
  }
  page.setTextDatum(MC_DATUM);
  page.drawString(vaultResultText(vaultResult), 270, 290);
  textStyle(page, 2);
  if (vaultResult == encrypted_seed_store::Result::ok) {
    page.drawString(sessionRecord ? lang::tr("AES-256-GCM / clave de sesion") :
                    "AES-256-GCM + PBKDF2 (600.000)", 270, 390);
    page.drawString(String(lang::tr("Archivo: ")) + vaultPath, 270, 445);
    page.drawString(lang::tr("La semilla sigue activa en memoria."), 270, 510);
  } else if (vaultResult == encrypted_seed_store::Result::exists) {
    page.drawString(lang::tr("El archivo existente"), 270, 400);
    page.drawString(lang::tr("no se ha sobrescrito."), 270, 445);
  }
  page.setTextDatum(TL_DATUM);
  buttonOn(page, kAction, "VOLVER AL MENU SEED", true, true);
  fullRefresh();
}

void saveVault() {
  if (strcmp(vaultPassword, vaultConfirmation) != 0) {
    encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
    vaultConfirmPhase = true;
    vaultMismatch = true;
    vaultRevealUntil = 0;
    drawVaultPassword();
    return;
  }
  snprintf(vaultPath, sizeof(vaultPath), "/%s-%s.vlt",
           activeFingerprint + 5, vaultLabel);
  blankPage();
  title("VAULT SEGURO", "Cifrando y verificando la tarjeta SD...");
  textStyle(page, 2); page.setCursor(30, 260);
  page.println(lang::tr("Puede tardar. No retires la tarjeta."));
  page.setCursor(30, 300);
  page.println(lang::tr("Derivando clave (PBKDF2)..."));
  fullRefresh(UPDATE_MODE_DU4);
  drawProgressBar(340, 0); progressPercent = 0;
  vaultResult = encrypted_seed_store::save(vaultPath, vaultPassword, words, targetWords, storeProgress);
  if (vaultResult == encrypted_seed_store::Result::ok) {
    uint16_t verifiedWords[24] = {}; uint8_t verifiedCount = 0;
    progressPercent = 0;
    const encrypted_seed_store::Result check = encrypted_seed_store::load(
        vaultPath, vaultPassword, verifiedWords, verifiedCount, storeProgress);
    if (check != encrypted_seed_store::Result::ok || verifiedCount != targetWords ||
        memcmp(verifiedWords, words, targetWords * sizeof(uint16_t)) != 0) {
      SD.remove(vaultPath);
      vaultResult = encrypted_seed_store::Result::wrong_password_or_tampered;
    }
    encrypted_seed_store::wipe(verifiedWords, sizeof(verifiedWords));
  }
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
  vaultConfirmPhase = false;
  vaultMismatch = false;
  vaultRevealUntil = 0;
  screen = Screen::vault_result; focusIndex = 0; drawVaultResult();
}

void beginVault() {
  vaultFlow = VaultFlow::individual;
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
  memset(vaultLabel, 0, sizeof(vaultLabel));
  vaultConfirmPhase = false;
  vaultMismatch = false;
  vaultRevealUntil = 0;
  screen = Screen::vault_label; focusIndex = 0; drawVaultLabel();
}

void beginSessionCreate() {
  vaultFlow = VaultFlow::session_create;
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
  memset(vaultLabel, 0, sizeof(vaultLabel));
  vaultConfirmPhase = false; vaultMismatch = false; vaultRevealUntil = 0;
  screen = Screen::vault_label; focusIndex = 0; drawVaultLabel();
}

void beginSessionSave() {
  if (!sessionUnlocked || !fingerprintValid) return;
  vaultFlow = VaultFlow::session_save_seed;
  memset(vaultLabel, 0, sizeof(vaultLabel));
  screen = Screen::vault_label; focusIndex = 0; drawVaultLabel();
}

void beginNewSeedFromSession(NewSeedIntent intent) {
  newSeedIntent = intent;
  resetPhrase(12);
  screen = Screen::length; focusIndex = 0; drawScreen();
}

void beginEntropyFromSession() {
  newSeedIntent = NewSeedIntent::to_vault;
  resetPhrase(12);
  screen = Screen::entropy_length; focusIndex = 0; drawScreen();
}

void scanVaultFiles() {
  vaultFileCount = 0; memset(vaultFiles, 0, sizeof(vaultFiles));
  if (SD.cardType() == CARD_NONE) return;
  File root = SD.open("/");
  if (!root || !root.isDirectory()) { if (root) root.close(); return; }
  File entry = root.openNextFile();
  while (entry && vaultFileCount < 6) {
    String name = entry.name();
    if (!entry.isDirectory() && name.endsWith(".vlt")) {
      if (!name.startsWith("/")) name = "/" + name;
      name.toCharArray(vaultFiles[vaultFileCount], sizeof(vaultFiles[0]));
      ++vaultFileCount;
    }
    entry.close(); entry = root.openNextFile();
  }
  if (entry) entry.close(); root.close();
}

const char* vaultDisplayName(uint8_t index) {
  if (index >= vaultFileCount) return "";
  return vaultFiles[index][0] == '/' ? vaultFiles[index] + 1 : vaultFiles[index];
}

void drawVaultList() {
  blankPage(); title(vaultDeleteMode ? "ELIMINAR VAULT" : "ABRIR VAULT",
                     vaultDeleteMode ? "Selecciona el archivo que quieres borrar" :
                     "Selecciona una copia cifrada de la SD");
  if (SD.cardType() == CARD_NONE) {
    textStyle(page, 3); page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("SD NO DETECTADA"), 270, 350); page.setTextDatum(TL_DATUM);
  } else if (!vaultFileCount) {
    textStyle(page, 3); page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("NO HAY ARCHIVOS .VLT"), 270, 350); page.setTextDatum(TL_DATUM);
  } else {
    for (uint8_t i = 0; i < vaultFileCount; ++i)
      buttonOn(page, kVaultFiles[i], vaultDisplayName(i), true, focusIndex == i);
  }
  buttonOn(page, kBack, "VOLVER", true, focusIndex == vaultFileCount);
  buttonOn(page, kAction, vaultDeleteMode ? "CANCELAR ELIMINACION" : "MODO ELIMINAR",
           vaultFileCount > 0, focusIndex == vaultFileCount + 1, Icon::trash);
  fullRefresh();
}

void openVaultList() {
  vaultDeleteMode = false; scanVaultFiles(); screen = Screen::vault_list; focusIndex = 0; drawVaultList();
}

void scanTxFiles() {
  txFileCount = 0; memset(txFiles, 0, sizeof(txFiles));
  if (SD.cardType() == CARD_NONE) return;
  File root = SD.open("/");
  if (!root || !root.isDirectory()) { if (root) root.close(); return; }
  File entry = root.openNextFile();
  while (entry && txFileCount < 6) {
    String name = entry.name();
    if (!entry.isDirectory() && name.endsWith(".psbt")) {
      if (!name.startsWith("/")) name = "/" + name;
      name.toCharArray(txFiles[txFileCount], sizeof(txFiles[0]));
      ++txFileCount;
    }
    entry.close(); entry = root.openNextFile();
  }
  if (entry) entry.close(); root.close();
}

const char* txDisplayName(uint8_t index) {
  if (index >= txFileCount) return "";
  return txFiles[index][0] == '/' ? txFiles[index] + 1 : txFiles[index];
}

void drawTxHistory() {
  blankPage();
  title("HISTORIAL", "Transacciones guardadas");
  if (SD.cardType() == CARD_NONE) {
    textStyle(page, 3); page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("SD NO DETECTADA"), 270, 350); page.setTextDatum(TL_DATUM);
  } else if (!txFileCount) {
    textStyle(page, 3); page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("NO HAY TRANSACCIONES"), 270, 350); page.setTextDatum(TL_DATUM);
  } else {
    for (uint8_t i = 0; i < txFileCount; ++i)
      buttonOn(page, kVaultFiles[i], txDisplayName(i), true, focusIndex == i);
  }
  buttonOn(page, kBack, "VOLVER", true, focusIndex == txFileCount);
  fullRefresh();
}

void openTxHistory() {
  scanTxFiles();
  screen = Screen::tx_history;
  focusIndex = 0;
  drawTxHistory();
}

void drawVaultUnlock() {
  const char* name = vaultFlow == VaultFlow::session_unlock ?
      sessionMetaFiles[selectedSessionFile] + 1 : vaultDisplayName(selectedVaultFile);
  blankPage(); title("DESBLOQUEAR VAULT", name);
  const size_t length = strlen(vaultPassword);
  textStyle(page, 2); page.setCursor(20, 155);
  page.println(vaultUnlockError ? lang::tr("CONTRASENA INCORRECTA O ARCHIVO ALTERADO")
                                : lang::tr("Introduce la contrasena del Vault"));
  page.drawRoundRect(20, 205, 500, 52, 8, kBlack); page.setCursor(35, 214);
  const bool revealed = vaultRevealUntil &&
      static_cast<int32_t>(vaultRevealUntil - millis()) > 0;
  if (revealed) page.print(vaultPassword);
  else for (size_t i = 0; i < length; ++i) page.print('*');
  drawKeyboardKeys();
  buttonOn(page, kDelete, "BORRAR", true, false, Icon::back);
  buttonOn(page, kAdd, "DESBLOQUEAR", length >= 1, false, Icon::unlock);
  buttonOn(page, kVaultReveal, revealed ? "VISIBLE 3 SEG." : "MOSTRAR 3 SEG.",
           length > 0, revealed, Icon::eye);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
  buttonOn(page, kAction, "DESBLOQUEAR", length >= 1, focusIndex == 1, Icon::unlock);
  fullRefresh();
}

void drawVaultLoaded() {
  blankPage(); title("VAULT RECUPERADO", "Checksum BIP39 valido");
  warningIcon(page, 270, 185);
  centeredFit(page, activeFingerprint, 350, 500, 3);
  char loadedText[48] = {};
  snprintf(loadedText, sizeof(loadedText), "%u palabras cargadas en memoria", targetWords);
  centeredFit(page, loadedText, 420);
  centeredFit(page, "Comprueba el fingerprint", 475);
  centeredFit(page, "antes de continuar.", 520);
  buttonOn(page, kAction, "ABRIR SEMILLA", true, true, Icon::folder);
  fullRefresh();
}

bool vaultUnlockBlocked() {
  if (vaultLockoutUntil == 0) return false;
  if (static_cast<uint32_t>(millis()) >= vaultLockoutUntil) { vaultLockoutUntil = 0; return false; }
  showToast("Demasiados intentos. Espera...");
  return true;
}

void vaultUnlockFailed() {
  vaultUnlockError = true;
  if (++vaultFailCount >= 5) { vaultLockoutUntil = millis() + 60000; vaultFailCount = 0; }
}

void loadSelectedVault() {
  if (vaultUnlockBlocked()) return;
  blankPage(); title("ABRIR VAULT", "Descifrando y verificando...");
  textStyle(page, 2); page.setCursor(30, 260); page.println(lang::tr("No retires la tarjeta SD."));
  page.setCursor(30, 300); page.println(lang::tr("Derivando clave (PBKDF2)..."));
  fullRefresh(UPDATE_MODE_DU4);
  drawProgressBar(340, 0); progressPercent = 0;
  uint16_t recovered[24] = {}; uint8_t recoveredCount = 0;
  const encrypted_seed_store::Result result = encrypted_seed_store::load(
      vaultFiles[selectedVaultFile], vaultPassword, recovered, recoveredCount, storeProgress);
  bool valid = result == encrypted_seed_store::Result::ok &&
      bip39::checksum_valid(recovered, recoveredCount);
  if (valid) {
    memset(words, 0, sizeof(words)); memcpy(words, recovered, recoveredCount * sizeof(uint16_t));
    targetWords = recoveredCount; wordCount = recoveredCount; prefix = ""; editingWord = -1;
    valid = updateFingerprint();
  }
  encrypted_seed_store::wipe(recovered, sizeof(recovered));
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  vaultRevealUntil = 0;
  if (!valid) {
    vaultUnlockFailed(); screen = Screen::vault_unlock; focusIndex = 0; drawVaultUnlock();
    return;
  }
  vaultUnlockError = false; vaultFailCount = 0; vaultLockoutUntil = 0;
  screen = Screen::vault_loaded; focusIndex = 0;
  drawVaultLoaded();
}

void scanSessionMeta() {
  sessionMetaCount = 0; memset(sessionMetaFiles, 0, sizeof(sessionMetaFiles));
  if (SD.cardType() == CARD_NONE) return;
  File root = SD.open("/"); if (!root) return; File entry = root.openNextFile();
  while (entry && sessionMetaCount < 6) {
    String name = entry.name();
    if (!entry.isDirectory() && name.endsWith(".svm")) {
      if (!name.startsWith("/")) name = "/" + name;
      name.toCharArray(sessionMetaFiles[sessionMetaCount++], sizeof(sessionMetaFiles[0]));
    }
    entry.close(); entry = root.openNextFile();
  }
  if (entry) entry.close(); root.close();
}

void scanSessionSeeds() {
  sessionSeedCount = 0; memset(sessionSeedFiles, 0, sizeof(sessionSeedFiles));
  if (!sessionUnlocked || SD.cardType() == CARD_NONE) return;
  char prefixName[16]; snprintf(prefixName, sizeof(prefixName), "S-%02X%02X%02X%02X-",
      sessionVaultId[0], sessionVaultId[1], sessionVaultId[2], sessionVaultId[3]);
  File root = SD.open("/"); if (!root) return; File entry = root.openNextFile();
  while (entry && sessionSeedCount < 6) {
    String name = entry.name(); if (name.startsWith("/")) name.remove(0, 1);
    if (!entry.isDirectory() && name.startsWith(prefixName) && name.endsWith(".svs")) {
      name = "/" + name;
      name.toCharArray(sessionSeedFiles[sessionSeedCount++], sizeof(sessionSeedFiles[0]));
    }
    entry.close(); entry = root.openNextFile();
  }
  if (entry) entry.close(); root.close();
}

uint8_t loadAllSessionSeeds() {
  scanSessionSeeds();
  LoadedSeed staged[kMaxLoadedSeeds] = {};
  uint8_t stagedCount = 0;
  for (uint8_t i = 0; i < sessionSeedCount && stagedCount < kMaxLoadedSeeds; ++i) {
    uint16_t recovered[24] = {}; uint8_t count = 0;
    uint8_t storedFpr[4] = {}, calculated[4] = {}; char label[17] = {};
    const auto result = session_vault_store::load_seed(sessionSeedFiles[i],
        sessionMasterKey, sessionVaultId, recovered, count, storedFpr, label);
    const bool valid = result == encrypted_seed_store::Result::ok &&
        bip39::checksum_valid(recovered, count) &&
        bitcoin_fingerprint::calculate(recovered, count, calculated) &&
        !memcmp(storedFpr, calculated, 4);
    if (valid) {
      LoadedSeed& item = staged[stagedCount++];
      memcpy(item.indices, recovered, count * sizeof(uint16_t)); item.count = count;
      snprintf(item.fingerprint, sizeof(item.fingerprint), "%02X%02X%02X%02X",
               calculated[0], calculated[1], calculated[2], calculated[3]);
      strncpy(item.label, label, sizeof(item.label) - 1); item.used = true;
      item.inVault = true;
    } else Serial.printf("Registro de sesion invalido omitido: %s\n", sessionSeedFiles[i]);
    encrypted_seed_store::wipe(recovered, sizeof(recovered));
    encrypted_seed_store::wipe(storedFpr, sizeof(storedFpr));
    encrypted_seed_store::wipe(calculated, sizeof(calculated));
  }
  if (stagedCount) {
    encrypted_seed_store::wipe(loadedSeeds, sizeof(loadedSeeds));
    memcpy(loadedSeeds, staged, stagedCount * sizeof(LoadedSeed));
    loadedSeedCount = stagedCount; activeLoadedSeed = -1;
    encrypted_seed_store::wipe(words, sizeof(words)); clearDerivedData();
    prefix = ""; wordCount = 0; editingWord = -1; clearFingerprint();
    activateLoadedSeed(0);
  }
  encrypted_seed_store::wipe(staged, sizeof(staged));
  return stagedCount;
}

void drawSessionMenu() {
  blankPage();
  title("VAULT DE SESION", sessionUnlocked ? sessionLabel : "Bloqueado");
  if (!sessionUnlocked) {
    buttonOn(page, kMenu[0], "CREAR VAULT", true, focusIndex == 0, Icon::plus);
    buttonOn(page, kMenu[1], "DESBLOQUEAR VAULT", true, focusIndex == 1, Icon::unlock);
    buttonOn(page, kMenu[2], "VOLVER", true, focusIndex == 2);
  } else {
    textStyle(page, 2); page.setCursor(25, 155);
    page.printf(lang::tr("Sesion activa: %s"), sessionLabel);
    buttonOn(page, kMenu[0], "CARGAR SEMILLA", true, focusIndex == 0, Icon::folder);
    buttonOn(page, kMenu[1], "BLOQUEAR VAULT", true, focusIndex == 1, Icon::lock);
    buttonOn(page, kMenu[2], "VOLVER", true, focusIndex == 2);
  }
  fullRefresh();
}

void drawSessionMetaList() {
  blankPage(); title("VAULT DE SESION", "Selecciona el Vault que quieres abrir");
  if (!sessionMetaCount) {
    textStyle(page, 3); page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("NO HAY VAULTS DE SESION"), 270, 350); page.setTextDatum(TL_DATUM);
  } else for (uint8_t i = 0; i < sessionMetaCount; ++i)
    buttonOn(page, kVaultFiles[i], sessionMetaFiles[i] + 1, true, focusIndex == i);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == sessionMetaCount); fullRefresh();
}

void drawSessionSeedList() {
  scanSessionSeeds(); blankPage();
  title(sessionDeleteMode ? "ELIMINAR SEMILLA" : "SEMILLAS DEL VAULT",
        sessionDeleteMode ? "Selecciona el registro que quieres borrar" : sessionLabel);
  if (!sessionSeedCount) {
    textStyle(page, 3); page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("VAULT VACIO"), 270, 350); page.setTextDatum(TL_DATUM);
  } else for (uint8_t i = 0; i < sessionSeedCount; ++i)
    buttonOn(page, kVaultFiles[i], sessionSeedFiles[i] + 1, true, focusIndex == i);
  if (!sessionDeleteMode) {
    buttonOn(page, kSessionNewVault, "CARGAR NUEVA SEED", true,
             focusIndex == sessionSeedCount, Icon::plus);
    buttonOn(page, kSessionNewEntropy, "GENERAR ENTROPIA", true,
             focusIndex == sessionSeedCount + 1, Icon::draw);
    buttonOn(page, kSessionNewRam, "CARGAR SOLO EN RAM", true,
             focusIndex == sessionSeedCount + 2, Icon::memory);
  }
  buttonOn(page, kSessionBack, "VOLVER", true,
           sessionDeleteMode ? focusIndex == sessionSeedCount
                              : focusIndex == sessionSeedCount + 3);
  buttonOn(page, kSessionAction, sessionDeleteMode ? "CANCELAR ELIMINACION" : "MODO ELIMINAR",
           sessionSeedCount > 0,
           sessionDeleteMode ? focusIndex == sessionSeedCount + 1
                             : focusIndex == sessionSeedCount + 4,
           Icon::trash);
  fullRefresh();
}

void drawDeleteConfirm() {
  blankPage(); title("CONFIRMAR ELIMINACION", deleteFailed ? "No se pudo borrar el archivo" :
                     "Esta operacion no se puede deshacer");
  warningIcon(page, 270, 185);
  textStyle(page, 2); page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("Se eliminara de la tarjeta SD:"), 270, 345);
  String display = pendingDeletePath[0] == '/' ? pendingDeletePath + 1 : pendingDeletePath;
  uint8_t size = 2; textStyle(page, size);
  while (size > 1 && page.textWidth(display) > 500) { --size; textStyle(page, size); }
  page.drawString(display, 270, 410);
  textStyle(page, 2); page.drawString(lang::tr("La semilla activa no se descarta."), 270, 480);
  page.setTextDatum(TL_DATUM);
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, "ELIMINAR ARCHIVO", true, focusIndex == 1, Icon::trash);
  fullRefresh();
}

void lockSessionVault() {
  if (entropySourceActive) { bootloader_random_disable(); entropySourceActive = false; }
  encrypted_seed_store::wipe(sessionMasterKey, sizeof(sessionMasterKey));
  encrypted_seed_store::wipe(sessionVaultId, sizeof(sessionVaultId));
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
  memset(sessionLabel, 0, sizeof(sessionLabel)); memset(sessionMetaPath, 0, sizeof(sessionMetaPath));
  memset(sessionMetaFiles, 0, sizeof(sessionMetaFiles));
  memset(sessionSeedFiles, 0, sizeof(sessionSeedFiles));
  sessionMetaCount = sessionSeedCount = 0;
  sessionUnlocked = false; clearPassphrase(); discardActiveSeed();
  M5.EPD.Clear(true); screen = Screen::menu; focusIndex = 0; drawMenu();
}

void createSessionVault() {
  snprintf(sessionMetaPath, sizeof(sessionMetaPath), "/SESSION-%s.svm", vaultLabel);
  blankPage();
  title("VAULT DE SESION", "Creando vault seguro...");
  textStyle(page, 2); page.setCursor(30, 260);
  page.println(lang::tr("Derivando la clave maestra (PBKDF2)."));
  page.setCursor(30, 300); page.println(lang::tr("Puede tardar varios segundos."));
  fullRefresh(UPDATE_MODE_DU4);
  drawProgressBar(340, 0); progressPercent = 0;
  const auto result = session_vault_store::create(sessionMetaPath, vaultLabel,
      vaultPassword, sessionMasterKey, sessionVaultId, storeProgress);
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
  if (result != encrypted_seed_store::Result::ok) {
    vaultResult = result; screen = Screen::vault_result; drawVaultResult(); return;
  }
  strncpy(sessionLabel, vaultLabel, sizeof(sessionLabel) - 1); sessionUnlocked = true;
  lastUserActivity = millis(); screen = Screen::session_menu; focusIndex = 0; drawSessionMenu();
}

void unlockSessionVault() {
  if (vaultUnlockBlocked()) return;
  blankPage();
  title("VAULT DE SESION", "DESBLOQUEANDO...");
  warningIcon(page, 270, 205);
  textStyle(page, 2); page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("Derivando la clave maestra"), 270, 365);
  page.drawString(lang::tr("Puede tardar varios segundos."), 270, 420);
  page.drawString(lang::tr("No retires la tarjeta SD."), 270, 475);
  page.setTextDatum(TL_DATUM);
  fullRefresh(UPDATE_MODE_DU4);
  delay(80);
  char unlockedLabel[17] = {};
  drawProgressBar(340, 0); progressPercent = 0;
  const auto result = session_vault_store::unlock(sessionMetaFiles[selectedSessionFile],
      vaultPassword, sessionMasterKey, sessionVaultId, unlockedLabel, storeProgress);
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword)); vaultRevealUntil = 0;
  if (result != encrypted_seed_store::Result::ok) {
    vaultUnlockFailed(); screen = Screen::vault_unlock; drawVaultUnlock(); return;
  }
  vaultUnlockError = false; vaultFailCount = 0; vaultLockoutUntil = 0;
  strncpy(sessionLabel, unlockedLabel, sizeof(sessionLabel) - 1);
  strncpy(sessionMetaPath, sessionMetaFiles[selectedSessionFile], sizeof(sessionMetaPath) - 1);
  sessionUnlocked = true; lastUserActivity = millis();
  const uint8_t loaded = loadAllSessionSeeds();
  Serial.printf("Semillas cargadas en RAM: %u\n", loaded);
  screen = Screen::active_seed; focusIndex = 0; drawActiveSeed();
}

void saveSeedToSession() {
  uint8_t rawFpr[4] = {};
  if (!sessionUnlocked || !bitcoin_fingerprint::calculate(words, targetWords, rawFpr)) return;
  char path[64]; snprintf(path, sizeof(path), "/S-%02X%02X%02X%02X-%02X%02X%02X%02X-%s.svs",
      sessionVaultId[0], sessionVaultId[1], sessionVaultId[2], sessionVaultId[3],
      rawFpr[0], rawFpr[1], rawFpr[2], rawFpr[3], vaultLabel);
  strncpy(vaultPath, path, sizeof(vaultPath) - 1);
  vaultResult = session_vault_store::save_seed(path, sessionMasterKey, sessionVaultId,
      vaultLabel, rawFpr, words, targetWords);
  if (vaultResult == encrypted_seed_store::Result::ok) {
    uint16_t verified[24] = {}; uint8_t verifiedCount = 0, verifiedFpr[4] = {};
    char verifiedLabel[17] = {};
    const auto check = session_vault_store::load_seed(path, sessionMasterKey, sessionVaultId,
        verified, verifiedCount, verifiedFpr, verifiedLabel);
    if (check != encrypted_seed_store::Result::ok || verifiedCount != targetWords ||
        memcmp(verified, words, targetWords * sizeof(uint16_t)) != 0 ||
        memcmp(verifiedFpr, rawFpr, 4) != 0) {
      SD.remove(path); vaultResult = encrypted_seed_store::Result::wrong_password_or_tampered;
    }
    encrypted_seed_store::wipe(verified, sizeof(verified));
    encrypted_seed_store::wipe(verifiedFpr, sizeof(verifiedFpr));
  }
  encrypted_seed_store::wipe(rawFpr, sizeof(rawFpr));
  if (vaultResult == encrypted_seed_store::Result::ok) cacheCurrentSeed(vaultLabel, true);
  lastUserActivity = millis();
  screen = Screen::vault_result; focusIndex = 0; drawVaultResult();
}

void loadSeedFromSession(uint8_t selected) {
  uint16_t recovered[24] = {}; uint8_t count = 0, storedFpr[4] = {}, calculated[4] = {};
  char label[17] = {};
  const auto result = session_vault_store::load_seed(sessionSeedFiles[selected],
      sessionMasterKey, sessionVaultId, recovered, count, storedFpr, label);
  bool valid = result == encrypted_seed_store::Result::ok && bip39::checksum_valid(recovered, count) &&
      bitcoin_fingerprint::calculate(recovered, count, calculated) && !memcmp(storedFpr, calculated, 4);
  if (valid) {
    char recoveredFingerprint[9] = {};
    snprintf(recoveredFingerprint, sizeof(recoveredFingerprint), "%02X%02X%02X%02X",
             calculated[0], calculated[1], calculated[2], calculated[3]);
    if (fingerprintValid) cacheCurrentSeed();
    const int8_t existing = findLoadedSeed(recoveredFingerprint);
    if (existing < 0 && loadedSeedCount >= kMaxLoadedSeeds) valid = false;
  }
  if (valid) {
    memset(words, 0, sizeof(words)); memcpy(words, recovered, count * sizeof(uint16_t));
    targetWords = wordCount = count; activeLoadedSeed = -1; clearDerivedData();
    valid = updateFingerprint() && cacheCurrentSeed(label, true);
  }
  encrypted_seed_store::wipe(recovered, sizeof(recovered));
  encrypted_seed_store::wipe(storedFpr, sizeof(storedFpr)); encrypted_seed_store::wipe(calculated, sizeof(calculated));
  if (!valid) {
    vaultResult = result == encrypted_seed_store::Result::ok ?
        encrypted_seed_store::Result::wrong_password_or_tampered : result;
    screen = Screen::vault_result; drawVaultResult(); return;
  }
  screen = Screen::vault_loaded; focusIndex = 0; drawVaultLoaded();
}

void commitWord(uint16_t selected) {
  if (selected == bip39::kInvalidWord) return;
  if (editingWord >= 0) {
    words[editingWord] = selected;
    editingWord = -1;
    prefix = "";
    updateFingerprint();
    screen = Screen::review;
    focusIndex = 0;
    drawReview();
    return;
  }
  if (wordCount >= targetWords) return;
  words[wordCount++] = selected;
  prefix = "";
  if (wordCount == targetWords) {
    updateFingerprint();
    if (newSeedIntent == NewSeedIntent::ram_only) cacheCurrentSeed("RAM");
    requestSecurity(Screen::review,
                    newSeedIntent != NewSeedIntent::none
                        ? Screen::session_seed_list : Screen::menu);
  } else {
    updateKeyboardDynamic();
  }
}

void editWord(uint8_t index) {
  if (index >= wordCount) return;
  editingWord = static_cast<int8_t>(index);
  prefix = "";
  screen = Screen::keyboard;
  focusIndex = 0;
  drawKeyboard();
}

int reviewWordAt(int x, int y) {
  if (y < 155) return -1;
  const int row = (y - 155) / 52;
  if (row < 0 || row >= 12) return -1;
  int index = row;
  if (targetWords == 24 && x >= 270) index += 12;
  if (targetWords == 12 && x >= 270) return -1;
  return index < wordCount ? index : -1;
}

void drawReview() {
  blankPage();
  title("REVISION",
        newSeedIntent == NewSeedIntent::to_vault
            ? "Semilla nueva para el Vault de sesion"
            : newSeedIntent == NewSeedIntent::ram_only
                ? "Semilla nueva que quedara solo en RAM"
                : "Toca una palabra para corregirla");
  textStyle(page, 2);
  for (uint8_t i = 0; i < targetWords; ++i) {
    const int column = targetWords == 24 && i >= 12 ? 1 : 0;
    const int row = targetWords == 24 ? i % 12 : i;
    page.setCursor(column ? 280 : 20, 155 + row * 52);
    page.printf("%02u %-12s", i + 1, bip39::word_at(words[i]));
  }
  const bool complete = wordCount == targetWords;
  const bool valid = complete && bip39::checksum_valid(words, targetWords);
  page.setCursor(20, 795);
  page.printf(lang::tr("Checksum: %s"), !complete ? lang::tr("INCOMPLETA") : valid ? lang::tr("VALIDO") : lang::tr("INVALIDO"));
  const char* actionLabel = newSeedIntent == NewSeedIntent::to_vault ? "GUARDAR EN VAULT" :
                            newSeedIntent == NewSeedIntent::ram_only ? "ACTIVAR EN RAM" :
                            "MENU SEED";
  const Icon actionIcon = newSeedIntent == NewSeedIntent::to_vault ? Icon::save :
                          newSeedIntent == NewSeedIntent::ram_only ? Icon::memory : Icon::none;
  buttonOn(page, kQrPrevious, "ULTIMA", true, focusIndex == 0, Icon::draw);
  buttonOn(page, kQrBack, actionLabel, valid, focusIndex == 1, actionIcon);
  buttonOn(page, kQrNext, "VER QR", valid, focusIndex == 2, Icon::qr);
  fullRefresh();
}

void drawActiveSeed() {
  blankPage();
  title("SEMILLA ACTIVA", "Acciones disponibles en memoria");
  static const Icon kActiveIcons[] = {Icon::key, Icon::shield, Icon::lock,
                                      Icon::eye, Icon::trash};
  for (uint8_t i = 0; i < 5; ++i) {
    const char* label = kActiveLabels[i];
    Icon icon = kActiveIcons[i];
    if (sessionUnlocked && i == 4) { label = "ACCIONES EN VAULT"; icon = Icon::folder; }
    buttonOn(page, kActiveMenu[i], label, true, focusIndex == i, icon);
  }
  buttonOn(page, kActiveMenu[5], "RECIBIR POR WIFI", true, focusIndex == 5,
           Icon::wifi);
  if (sessionUnlocked) {
    buttonOn(page, kActiveMenu[6], "CERRAR VAULT", true, focusIndex == 6,
             Icon::lock);
  }
  const uint8_t settingsIdx = sessionUnlocked ? 7 : 6;
  const uint8_t menuIdx = sessionUnlocked ? 8 : 7;
  buttonOn(page, kActiveMenu[settingsIdx], "AJUSTES", true,
           focusIndex == settingsIdx, Icon::wrench);
  buttonOn(page, kActiveMenu[menuIdx], "VOLVER AL MENU", true,
           focusIndex == menuIdx, Icon::home);
  textStyle(page, 2);
  page.setTextDatum(MC_DATUM);
  int footerY = 800;
  const bool ramOnly = (activeLoadedSeed >= 0 &&
                        !loadedSeeds[activeLoadedSeed].inVault) ||
                       (activeLoadedSeed < 0 && fingerprintValid);
  if (ramOnly) {
    page.drawString(lang::tr("SEED SOLO EN RAM - NO EN VAULT"), 270, footerY);
    footerY += 36;
  }
  if (passphraseActive) {
    page.drawString(lang::tr("PASSPHRASE: ACTIVA EN RAM"), 270, footerY);
    footerY += 36;
  }
  textStyle(page, 1);
  page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr(activeHint(focusIndex)), 270, 940);
  textStyle(page, 2);
  page.setTextDatum(TL_DATUM);
  fullRefresh();
}

void drawSeedSwitcher() {
  blankPage(); title("SEMILLAS EN MEMORIA", "Selecciona la semilla activa");
  for (uint8_t i = 0; i < loadedSeedCount; ++i) {
    String name = loadedSeeds[i].fingerprint;
    name += "  ";
    if (loadedSeeds[i].inVault)
      name += loadedSeeds[i].label[0] ? loadedSeeds[i].label : "SIN ETIQUETA";
    else name += "[RAM]";
    buttonOn(page, kVaultFiles[i], name.c_str(), true,
             activeLoadedSeed == static_cast<int8_t>(i) || focusIndex == i);
  }
  buttonOn(page, kBack, "VOLVER", true, focusIndex == loadedSeedCount);
  fullRefresh();
}

void drawBackupSeed() {
  blankPage();
  title("BACKUP SEED", "Copias y comprobacion de la semilla");
  static const Icon kBackupIcons[] = {Icon::list, Icon::qr, Icon::qr,
                                      Icon::lock, Icon::none};
  if (sessionUnlocked) {
    buttonOn(page, kActiveMenu[0], "VER PALABRAS", true, focusIndex == 0, Icon::list);
    buttonOn(page, kActiveMenu[1], "VER QR", true, focusIndex == 1, Icon::qr);
    buttonOn(page, kActiveMenu[2], "BACKUP SEEDQR", true, focusIndex == 2, Icon::qr);
    buttonOn(page, kActiveMenu[3], "VOLVER", true, focusIndex == 3);
  } else {
    for (uint8_t i = 0; i < 5; ++i)
      buttonOn(page, kActiveMenu[i], kBackupLabels[i], true, focusIndex == i,
               kBackupIcons[i]);
  }
  fullRefresh();
}

void drawVaultActions() {
  blankPage();
  title("ACCIONES EN VAULT", sessionLabel);
  buttonOn(page, kActiveMenu[0], "CARGAR SEMILLA", true, focusIndex == 0,
           Icon::folder);
  buttonOn(page, kActiveMenu[1], "GUARDAR SEMILLA ACTIVA", fingerprintValid,
           focusIndex == 1, Icon::save);
  buttonOn(page, kActiveMenu[2], "BLOQUEAR VAULT", true, focusIndex == 2,
           Icon::lock);
  buttonOn(page, kActiveMenu[3], "VOLVER", true, focusIndex == 3);
  fullRefresh();
}

void warningIcon(M5EPD_Canvas& canvas, int cx, int top) {
  const int halfWidth = 58;
  const int bottom = top + 105;
  canvas.fillTriangle(cx, top, cx - halfWidth, bottom,
                      cx + halfWidth, bottom, kBlack);
  canvas.fillTriangle(cx, top + 16, cx - halfWidth + 15, bottom - 10,
                      cx + halfWidth - 15, bottom - 10, kWhite);
  canvas.fillRect(cx - 5, top + 38, 10, 37, kBlack);
  canvas.fillCircle(cx, top + 88, 6, kBlack);
}

void drawSecurityWarning() {
  blankPage();
  title("SEGURIDAD", "Antes de mostrar la semilla");
  warningIcon(page, 270, 175);
  centeredFit(page, "COMPRUEBA TU ENTORNO", 335, 500, 3);
  centeredFit(page, "Busca un lugar privado.", 400);
  centeredFit(page, "Evita camaras y ventanas.", 445);
  centeredFit(page, "Comprueba que estas solo.", 490);
  centeredFit(page, "No permitas fotos de la pantalla.", 535);
  centeredFit(page, "Vas a mostrar datos sensibles.", 580);
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, "ESTOY EN UN LUGAR SEGURO", true, focusIndex == 1,
           Icon::shield);
  fullRefresh();
}

void requestSecurity(Screen target, Screen returnTo) {
  securityWarningReturn = returnTo;
  securityWarningTarget = target;
  screen = Screen::security_warning;
  focusIndex = 0;
  drawSecurityWarning();
}

void drawSessionLockWarning() {
  blankPage();
  title("LIMPIEZA DE SEED", "Por inactividad");
  warningIcon(page, 270, 200);
  const uint32_t remaining = gSettings.seedCleanTimeoutMs -
      static_cast<uint32_t>(millis() - lastUserActivity);
  const uint32_t sec = remaining / 1000 + 1;
  textStyle(page, 3); page.setTextDatum(MC_DATUM);
  page.drawString(String(lang::tr("Se limpiara en ")) + sec + " s", 270, 380);
  textStyle(page, 2); page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("Toca la pantalla o pulsa"), 270, 470);
  page.drawString(lang::tr("la palanca para continuar."), 270, 515);
  page.drawString(lang::tr("La semilla se borrara de RAM."), 270, 560);
  page.setTextDatum(TL_DATUM);
  fullRefresh(UPDATE_MODE_DU4);
}

bool buildSeedQR() {
  if (!bip39::checksum_valid(words, targetWords)) return false;
  char payload[97] = {};
  for (uint8_t i = 0; i < targetWords; ++i) {
    const uint16_t value = words[i];
    snprintf(payload + i * 4, 5, "%04u", value);
  }
  return qrcode_initText(&seedqr, seedqrBuffer, targetWords == 12 ? 2 : 3,
                         ECC_LOW, payload) == 0;
}

struct QrRun { bool black; uint8_t start; uint8_t length; uint8_t total; };

QrRun qrRunAt(uint8_t row, uint8_t wanted) {
  QrRun result{false, 0, 0, 0};
  if (row >= seedqr.size) return result;
  bool color = qrcode_getModule(&seedqr, 0, row);
  uint8_t start = 0, runIndex = 0;
  for (uint8_t x = 1; x <= seedqr.size; ++x) {
    const bool next = x < seedqr.size ? qrcode_getModule(&seedqr, x, row) : !color;
    if (x < seedqr.size && next == color) continue;
    if (runIndex == wanted) result = QrRun{color, start, static_cast<uint8_t>(x - start), 0};
    ++runIndex; start = x; color = next;
  }
  result.total = runIndex;
  return result;
}

bool qrHasPrevious() { return seedqrRow > 0 || seedqrRun > 0; }
bool qrHasNext() {
  const QrRun run = qrRunAt(seedqrRow, seedqrRun);
  return seedqrRun + 1 < run.total || seedqrRow + 1 < seedqr.size;
}

void qrNextStep() {
  const QrRun run = qrRunAt(seedqrRow, seedqrRun);
  if (seedqrRun + 1 < run.total) ++seedqrRun;
  else if (seedqrRow + 1 < seedqr.size) { ++seedqrRow; seedqrRun = 0; }
}

void qrPreviousStep() {
  if (seedqrRun > 0) --seedqrRun;
  else if (seedqrRow > 0) {
    --seedqrRow;
    const QrRun first = qrRunAt(seedqrRow, 0);
    seedqrRun = first.total ? first.total - 1 : 0;
  }
}

void drawPlainQR() {
  blankPage();
  title("SEEDQR", "QR limpio de la semilla activa");
  const int module = seedqr.size == 25 ? 18 : 15;
  const int pixels = seedqr.size * module;
  const int ox = (kWidth - pixels) / 2;
  const int oy = 190;
  page.fillRect(ox - 16, oy - 16, pixels + 32, pixels + 32, kWhite);
  for (uint8_t y = 0; y < seedqr.size; ++y)
    for (uint8_t x = 0; x < seedqr.size; ++x)
      if (qrcode_getModule(&seedqr, x, y))
        page.fillRect(ox + x * module, oy + y * module, module, module, kBlack);
  buttonOn(page, kAction, "VOLVER AL MENU", true, true);
  fullRefresh();
}

void renderQrDynamic() {
  const int module = seedqr.size == 25 ? 15 : 13;
  const int qrPixels = seedqr.size * module;
  const int originX = (kWidth - qrPixels) / 2;
  const int originY = 165;
  M5EPD_Canvas marker(&M5.EPD);
  if (marker.createCanvas(24, qrPixels)) {
    marker.fillCanvas(kWhite);
    const int cy = seedqrRow * module + module / 2;
    marker.fillTriangle(22, cy, 5, cy - 8, 5, cy + 8, kBlack);
    marker.pushCanvas(originX - 28, originY, UPDATE_MODE_A2);
    marker.fillCanvas(kWhite);
    marker.fillTriangle(2, cy, 19, cy - 8, 19, cy + 8, kBlack);
    marker.pushCanvas(originX + qrPixels + 4, originY, UPDATE_MODE_A2);
    marker.deleteCanvas();
  }
  M5EPD_Canvas zoom(&M5.EPD);
  if (zoom.createCanvas(520, 250)) {
    zoom.fillCanvas(kWhite);
    textStyle(zoom, 2);
    zoom.setCursor(5, 5);
    const QrRun active = qrRunAt(seedqrRow, seedqrRun);
    zoom.printf("FILA %02u/%02u   PASO %02u/%02u", seedqrRow + 1,
                seedqr.size, seedqrRun + 1, active.total);
    const int cell = seedqr.size == 25 ? 19 : 16;
    const int zx = (520 - seedqr.size * cell) / 2;
    for (uint8_t x = 0; x < seedqr.size; ++x) {
      const bool black = qrcode_getModule(&seedqr, x, seedqrRow);
      if (black) zoom.fillRect(zx + x * cell, 55, cell, cell, kBlack);
      else zoom.drawRect(zx + x * cell, 55, cell, cell, kBlack);
    }
    const int markX = zx + active.start * cell;
    const int markW = active.length * cell;
    zoom.drawFastHLine(markX, 82, markW, kBlack);
    zoom.drawFastVLine(markX, 76, 12, kBlack);
    zoom.drawFastVLine(markX + markW - 1, 76, 12, kBlack);
    String instruction = String(active.length) + " ";
    instruction += active.length == 1 ? "CASILLA " : "CASILLAS ";
    instruction += active.black ? (active.length == 1 ? "NEGRA" : "NEGRAS")
                                : (active.length == 1 ? "BLANCA" : "BLANCAS");
    uint8_t instructionSize = 3;
    textStyle(zoom, instructionSize);
    while (instructionSize > 1 && zoom.textWidth(instruction) > 490) {
      --instructionSize;
      textStyle(zoom, instructionSize);
    }
    zoom.setTextDatum(MC_DATUM);
    zoom.drawString(instruction, 260, 155);
    textStyle(zoom, 2);
    zoom.setTextDatum(MC_DATUM);
    String columns = "Columnas " + String(active.start + 1) + " - " +
                     String(active.start + active.length);
    zoom.drawString(columns, 260, 220);
    zoom.pushCanvas(10, 565, UPDATE_MODE_DU4);
    zoom.deleteCanvas();
  }
  updateButton(kQrPrevious, "ANTERIOR", qrHasPrevious(), focusIndex == 0, Icon::back);
  updateButton(kQrNext, "SIGUIENTE", qrHasNext(), focusIndex == 2, Icon::forward);
}

void drawSeedQR() {
  blankPage();
  title("BACKUP SEEDQR", "Asistente de dibujo fila a fila");
  const int module = seedqr.size == 25 ? 15 : 13;
  const int pixels = seedqr.size * module;
  const int ox = (kWidth - pixels) / 2;
  for (uint8_t y = 0; y < seedqr.size; ++y)
    for (uint8_t x = 0; x < seedqr.size; ++x)
      if (qrcode_getModule(&seedqr, x, y))
        page.fillRect(ox + x * module, 165 + y * module, module, module, kBlack);
  buttonOn(page, kQrPrevious, "ANTERIOR", qrHasPrevious(), focusIndex == 0, Icon::back);
  buttonOn(page, kQrBack, "SALIR", true, focusIndex == 1, Icon::x);
  buttonOn(page, kQrNext, "SIGUIENTE", qrHasNext(), focusIndex == 2, Icon::forward);
  fullRefresh();
  renderQrDynamic();
}

bool derivePublicKey(uint8_t profile) {
  publicExtendedKey = "";
  publicKeyProfile = profile % kPublicProfileCount;
  if (!fingerprintValid || !hdSelfTest) return false;
  const PublicProfile& selected = kPublicProfiles[publicKeyProfile];
  return bitcoin_hd::account_key(words, targetWords, selected.purpose,
                                 selected.version, publicExtendedKey,
                                 passphraseActive ? activePassphrase : "");
}

void drawPublicKey() {
  const PublicProfile& selected = kPublicProfiles[publicKeyProfile];
  blankPage();
  title(selected.title, selected.type);
  textStyle(page, 2);
  page.setCursor(20, 170);
  page.printf("Mainnet  %s", selected.path);
  page.setCursor(20, 215);
  page.println(lang::tr("Revela direcciones e historial."));
  page.setCursor(20, 255);
  page.println(lang::tr("No permite gastar."));
  if (!hdSelfTest || !publicExtendedKey.length()) {
    textStyle(page, 3);
    page.setCursor(20, 340);
    page.println(lang::tr("ERROR DE DERIVACION"));
  } else {
    textStyle(page, 2);
    constexpr uint8_t charsPerLine = 36;
    for (uint8_t line = 0; line < 4; ++line) {
      const unsigned start = line * charsPerLine;
      if (start >= publicExtendedKey.length()) break;
      page.setCursor(20, 335 + line * 58);
      page.println(publicExtendedKey.substring(start, start + charsPerLine));
    }
  }
  buttonOn(page, kPublicQr, "MOSTRAR QR", publicExtendedKey.length(), focusIndex == 0, Icon::qr);
  buttonOn(page, kQrPrevious, "ANTERIOR", true, focusIndex == 1, Icon::back);
  buttonOn(page, kQrBack, "MENU SEED", true, focusIndex == 2, Icon::home);
  buttonOn(page, kQrNext, "SIGUIENTE", true, focusIndex == 3, Icon::forward);
  fullRefresh();
}

bool buildPublicKeyQr() {
  memset(publicKeyQrBuffer, 0, sizeof(publicKeyQrBuffer));
  if (!publicExtendedKey.length()) return false;
  return qrcode_initText(&publicKeyQr, publicKeyQrBuffer, 6, ECC_LOW,
                         publicExtendedKey.c_str()) == 0;
}

void drawPublicKeyQr() {
  const PublicProfile& selected = kPublicProfiles[publicKeyProfile];
  blankPage();
  title("QR CLAVE PUBLICA", selected.path);
  const int module = 10;
  const int pixels = publicKeyQr.size * module;
  const int ox = (kWidth - pixels) / 2;
  const int oy = 205;
  page.fillRect(ox - 20, oy - 20, pixels + 40, pixels + 40, kWhite);
  for (uint8_t y = 0; y < publicKeyQr.size; ++y)
    for (uint8_t x = 0; x < publicKeyQr.size; ++x)
      if (qrcode_getModule(&publicKeyQr, x, y))
        page.fillRect(ox + x * module, oy + y * module, module, module, kBlack);
  textStyle(page, 2);
  page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("CLAVE PUBLICA - DATOS SENSIBLES"), 270, 700);
  page.setTextDatum(TL_DATUM);
  buttonOn(page, kAction, "VOLVER A CLAVE", true, true);
  fullRefresh();
}

void openPublicKey(uint8_t profile) {
  blankPage();
  title("CLAVE PUBLICA", "Calculando y verificando derivacion...");
  fullRefresh(UPDATE_MODE_DU4);
  derivePublicKey(profile);
  screen = Screen::public_key;
  focusIndex = 0;
  drawPublicKey();
}

bool updateAddress() {
  activeAddress = "";
  if (!fingerprintValid || !hdSelfTest) return false;
  if (publicKeyProfile == 2 && !addressBip84SelfTest) return false;
  return bitcoin_address::derive(words, targetWords,
      kPublicProfiles[publicKeyProfile].purpose, addressChange,
      addressIndex, activeAddress, passphraseActive ? activePassphrase : "");
}

void drawAddressExplorer() {
  const PublicProfile& profile = kPublicProfiles[publicKeyProfile];
  blankPage(); title("DIRECCIONES", profile.type);
  textStyle(page, 2); page.setCursor(20, 160);
  page.printf(lang::tr("Ruta: %s/%u/%lu"), profile.path, addressChange,
              static_cast<unsigned long>(addressIndex));
  page.setCursor(20, 210);
  page.printf(lang::tr("Rama: %s"), addressChange ? lang::tr("CAMBIO") : lang::tr("RECIBIR"));
  buttonOn(page, kAddressValue, activeAddress.length() ? "" : "ERROR DE DERIVACION");
  if (activeAddress.length()) {
    String lines[4]; uint8_t lineCount = 0;
    for (unsigned position = 0; position < activeAddress.length(); position += 4) {
      if (lineCount >= 4) break;
      if (lines[lineCount].length()) lines[lineCount] += ' ';
      lines[lineCount] += activeAddress.substring(position, position + 4);
      // Cuatro grupos por linea: lectura facil sin modificar la direccion real.
      if (((position / 4) + 1) % 4 == 0 && position + 4 < activeAddress.length())
        ++lineCount;
    }
    if (lines[lineCount].length()) ++lineCount;
    textStyle(page, 3); page.setTextDatum(MC_DATUM);
    const int firstY = kAddressValue.y + kAddressValue.h / 2 -
                       (static_cast<int>(lineCount) - 1) * 23;
    for (uint8_t i = 0; i < lineCount; ++i)
      page.drawString(lines[i], 270, firstY + i * 46);
    page.setTextDatum(TL_DATUM);
  }
  buttonOn(page, kAddressReceive, "RECIBIR", true, focusIndex == 0, Icon::down);
  buttonOn(page, kAddressChange, "CAMBIO", true, focusIndex == 1, Icon::up);
  buttonOn(page, kAddressMinus, "- 1", addressIndex > 0, focusIndex == 2, Icon::minus);
  buttonOn(page, kAddressIndex, String(addressIndex).c_str(), true);
  buttonOn(page, kAddressPlus, "+ 1", addressIndex < 999999, focusIndex == 3, Icon::plus);
  String nextProfile = String("TIPO: ") + profile.title;
  buttonOn(page, kAddressProfile, nextProfile.c_str(), true, focusIndex == 4);
  buttonOn(page, kBack, "MENU SEED", true, focusIndex == 5, Icon::home);
  buttonOn(page, kAction, "QR DIRECCION", activeAddress.length(), focusIndex == 6,
           Icon::qr);
  textStyle(page, 1); page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("Toca el indice para ir a uno concreto (0-999999)"), 270, 765);
  page.setTextDatum(TL_DATUM);
  fullRefresh();
}

void updateAddressIndexDynamic() {
  M5EPD_Canvas field(&M5.EPD);
  if (field.createCanvas(500, 52)) {
    field.fillCanvas(kWhite); field.drawRoundRect(0, 0, 500, 52, 8, kBlack);
    textStyle(field, 2); field.setCursor(15, 9);
    field.print(indexBuffer[0] ? indexBuffer : "0");
    field.pushCanvas(20, 165, UPDATE_MODE_A2); field.deleteCanvas();
  }
  updateButton(kDigitDelete, "BORRAR", indexBuffer[0], false, Icon::back, UPDATE_MODE_A2);
  updateButton(kAction, "IR A INDICE", indexBuffer[0], focusIndex == 1, Icon::check, UPDATE_MODE_A2);
}

void drawAddressIndexInput() {
  blankPage();
  title("IR A INDICE", "Escribe el numero de indice (0-999999)");
  page.drawRoundRect(20, 165, 500, 52, 8, kBlack);
  textStyle(page, 2); page.setCursor(35, 174);
  page.print(indexBuffer[0] ? indexBuffer : "0");
  for (uint8_t i = 0; i < 10; ++i)
    buttonOn(page, kDigitKey[i], String(i == 9 ? 0 : i + 1).c_str());
  buttonOn(page, kDigitDelete, "BORRAR", indexBuffer[0], false, Icon::back);
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, "IR A INDICE", indexBuffer[0], focusIndex == 1, Icon::check);
  fullRefresh();
}

void openAddressExplorer() {
  publicKeyProfile = gSettings.defaultProfile;
  addressChange = 0; addressIndex = 0;
  updateAddress(); screen = Screen::address_explorer; focusIndex = 0;
  drawAddressExplorer();
}

bool buildAddressQr() {
  memset(addressQrBuffer, 0, sizeof(addressQrBuffer));
  return activeAddress.length() && qrcode_initText(&addressQr, addressQrBuffer,
      4, ECC_LOW, activeAddress.c_str()) == 0;
}

void drawAddressQr() {
  blankPage(); title("QR DIRECCION", addressChange ? "Cambio" : "Recibir");
  const int module = 11, pixels = addressQr.size * module;
  const int ox = (kWidth - pixels) / 2, oy = 205;
  page.fillRect(ox - 20, oy - 20, pixels + 40, pixels + 40, kWhite);
  for (uint8_t y = 0; y < addressQr.size; ++y)
    for (uint8_t x = 0; x < addressQr.size; ++x)
      if (qrcode_getModule(&addressQr, x, y))
        page.fillRect(ox + x * module, oy + y * module, module, module, kBlack);
  textStyle(page, 1); page.setTextDatum(MC_DATUM);
  page.drawString(activeAddress, 270, 650); page.setTextDatum(TL_DATUM);
  buttonOn(page, kAction, "VOLVER AL EXPLORADOR", true, true); fullRefresh();
}

void drawDiscardConfirm() {
  blankPage();
  title("DESCARTAR SEED", "Esta accion elimina la semilla de RAM");
  textStyle(page, 2);
  page.setCursor(30, 220); page.println(lang::tr("Comprueba el fingerprint"));
  page.setCursor(30, 260); page.println(lang::tr("antes de continuar."));
  page.setCursor(30, 320); page.println(lang::tr("No se puede deshacer."));
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, "CONFIRMAR DESCARTE", true, focusIndex == 1, Icon::trash);
  fullRefresh();
}

void drawUnlockConfirm() {
  blankPage();
  title("ABRIR VAULT", "Hay una semilla activa en RAM");
  warningIcon(page, 270, 200);
  textStyle(page, 2); page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("Al abrir el vault se descartara"), 270, 360);
  page.drawString(lang::tr("la semilla que esta activa ahora."), 270, 405);
  page.drawString(lang::tr("Si no esta guardada, se perdera."), 270, 460);
  page.setTextDatum(TL_DATUM);
  buttonOn(page, kBack, "CANCELAR", true, focusIndex == 0);
  buttonOn(page, kAction, "CONTINUAR", true, focusIndex == 1, Icon::folder);
  fullRefresh();
}

void drawDiagnostics() {
  blankPage();
  title("DIAGNOSTICO", "Controlador nativo M5EPD");
  textStyle(page, 2);
  page.setCursor(25, 180);
  page.println(lang::tr("Pantalla: 540 x 960"));
  page.setCursor(25, 235);
  page.println(lang::tr("Tactil GT911: activo"));
  page.setCursor(25, 290);
  page.println(lang::tr("Refresco: Canvas A2 / DU4"));
  page.setCursor(25, 345);
  page.printf("BIP39: %s", bip39::self_test() ? "OK" : "ERROR");
  page.setCursor(25, 400);
  page.printf("BIP32 xpub/zpub: %s", hdSelfTest ? "OK" : "ERROR");
  page.setCursor(25, 455);
  page.printf(lang::tr("microSD: %s"), SD.cardType() == CARD_NONE ? lang::tr("NO DETECTADA") : "OK");
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
  fullRefresh();
}

void drawHelp() {
  blankPage();
  title("AYUDA", "Conceptos basicos");
  static const char* lines[] = {
    "VAULT DE SESION: varias semillas cifradas",
    "bajo una unica contrasena maestra.",
    "",
    "VAULT INDIVIDUAL: una sola semilla cifrada",
    "con su propia contrasena (archivo .vlt).",
    "",
    "SOLO RAM: la semilla no se guarda y se",
    "borra al apagar o al descartarla.",
    "",
    "PASSPHRASE: palabra extra (BIP39) que",
    "cambia TODAS tus direcciones.",
    "",
    "FINGERPRINT: identificador corto de tu",
    "semilla para verificarla visualmente.",
    "",
    "ENTROPIA: aleatoriedad que genera la",
    "semilla dibujando o tirando dados.",
  };
  int y = 165;
  for (const char* line : lines) {
    page.setCursor(20, y);
    page.println(lang::tr(line));
    y += 38;
  }
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
  fullRefresh();
}

qr_ble::QRBLEClient qrClient;
qr_ble::Phase lastQrPhase = qr_ble::Phase::Idle;
uint16_t lastQrChunks = 0;
uint8_t lastQrProgress = 255;
String lastQrStatus;

bool scanQrActive() {
  const auto p = qrClient.phase();
  return p == qr_ble::Phase::Scanning || p == qr_ble::Phase::Connecting ||
         p == qr_ble::Phase::Waiting || p == qr_ble::Phase::Receiving;
}

const char* scanSubtitle() {
  switch (qrClient.phase()) {
    case qr_ble::Phase::Scanning: return "Buscando camara...";
    case qr_ble::Phase::Connecting: return "Camara encontrada. Conectando...";
    case qr_ble::Phase::Waiting: return "Camara conectada. Esperando QR...";
    case qr_ble::Phase::Receiving: return "Recibiendo el QR...";
    case qr_ble::Phase::Success: return "Transferencia completada";
    case qr_ble::Phase::Failed: return "La transferencia ha fallado";
    default: return "";
  }
}

String scanStatusLine() {
  const auto p = qrClient.phase();
  if (p == qr_ble::Phase::Scanning) return "Buscando camara...";
  if (p == qr_ble::Phase::Connecting) return "Conectando...";
  if (p == qr_ble::Phase::Waiting) {
    const String& s = qrClient.statusText();
    if (s == "QR_DETECTED") return "QR detectado";
    if (s == "SCANNING") return "Camara escaneando...";
    if (s == "TRANSFER_START") return "Iniciando transferencia...";
    return "Esperando QR...";
  }
  if (p == qr_ble::Phase::Receiving) return "Recibiendo...";
  return "";
}

const char* scanErrorText(qr_ble::Error e) {
  switch (e) {
    case qr_ble::Error::BleInit: return "Error de inicializacion BLE";
    case qr_ble::Error::ScanTimeout: return "No se encontro la camara";
    case qr_ble::Error::ConnectTimeout:
    case qr_ble::Error::ConnectFailed: return "No se pudo conectar";
    case qr_ble::Error::ServiceNotFound: return "Servicio BLE no encontrado";
    case qr_ble::Error::SubscribeFailed: return "No se pudo suscribir";
    case qr_ble::Error::Disconnected: return "Camara desconectada";
    case qr_ble::Error::PayloadTooLarge: return "PAYLOAD DEMASIADO GRANDE";
    case qr_ble::Error::InvalidTransfer: return "TRANSFERENCIA INVALIDA";
    case qr_ble::Error::TransferTimeout: return "Transferencia agotada";
    default: return "ERROR";
  }
}

bool isValidUtf8(const std::vector<uint8_t>& d) {
  size_t i = 0;
  while (i < d.size()) {
    const uint8_t c = d[i];
    if (c < 0x80) { ++i; continue; }
    if ((c & 0xE0) == 0xC0) {
      if (i + 1 >= d.size() || (d[i + 1] & 0xC0) != 0x80) return false;
      i += 2;
    } else if ((c & 0xF0) == 0xE0) {
      if (i + 2 >= d.size() || (d[i + 1] & 0xC0) != 0x80 ||
          (d[i + 2] & 0xC0) != 0x80) return false;
      i += 3;
    } else if ((c & 0xF8) == 0xF0) {
      if (i + 3 >= d.size() || (d[i + 1] & 0xC0) != 0x80 ||
          (d[i + 2] & 0xC0) != 0x80 || (d[i + 3] & 0xC0) != 0x80) return false;
      i += 4;
    } else {
      return false;
    }
  }
  return true;
}

String scanPayloadText(const std::vector<uint8_t>& d) {
  String s;
  s.reserve(d.size());
  for (uint8_t c : d) {
    if (c == '\r') s += '\n';
    else if (c >= 0x20 || c == '\n') s += static_cast<char>(c);
  }
  return s;
}

void drawWrappedText(M5EPD_Canvas& c, const String& text, int x, int y,
                     int width, int lineHeight, int maxLines) {
  textStyle(c, 1);
  size_t pos = 0;
  const size_t len = text.length();
  int line = 0;
  while (pos < len && line < maxLines) {
    size_t end = pos;
    String lineStr;
    while (end < len && text[end] != '\n') {
      const String sub = text.substring(pos, end + 1);
      if (c.textWidth(sub) > width) break;
      lineStr = sub;
      ++end;
    }
    if (end == pos && end < len) {
      lineStr = text.substring(pos, pos + 1);
      ++end;
    }
    c.setCursor(x, y + line * lineHeight);
    c.print(lineStr);
    ++line;
    if (end < len && text[end] == '\n') ++end;
    pos = end;
  }
  if (pos < len) {
    c.setCursor(x, y + line * lineHeight);
    c.print("...");
  }
}

void drawScanStatusInto(M5EPD_Canvas& c, int ox, int oy) {
  const auto p = qrClient.phase();
  if (p == qr_ble::Phase::Receiving) {
    textStyle(c, 2);
    c.setTextDatum(MC_DATUM);
    c.drawString("Recibiendo...", ox + 250, oy + 40);
    c.drawString(String(qrClient.receivedChunks()) + " / " +
                     qrClient.totalChunks(), ox + 250, oy + 90);
    c.setTextDatum(TL_DATUM);
  } else {
    textStyle(c, 3);
    c.setTextDatum(MC_DATUM);
    c.drawString(scanStatusLine(), ox + 250, oy + 80);
    c.setTextDatum(TL_DATUM);
  }
}

void drawScanQrSuccess() {
  const qr_ble::QRPayload& pl = qrClient.payload();
  textStyle(page, 2);
  page.setCursor(30, 175);
  page.printf("Format: %s", pl.format.c_str());
  page.setCursor(30, 220);
  page.printf("Type: %s", pl.type.c_str());
  page.setCursor(30, 265);
  page.printf("Size: %u bytes", static_cast<unsigned>(pl.data.size()));
  page.setCursor(30, 310);
  page.println("Content:");
  page.drawRoundRect(20, 345, 500, 385, 8, kBlack);
  if (!pl.data.empty() && isValidUtf8(pl.data)) {
    drawWrappedText(page, scanPayloadText(pl.data), 32, 358, 470, 22, 14);
  } else {
    textStyle(page, 2);
    page.setTextDatum(MC_DATUM);
    page.drawString("Binary payload / " + String(pl.data.size()) + " bytes",
                    270, 520);
    page.setTextDatum(TL_DATUM);
  }
  buttonOn(page, kAction, "VOLVER", true, focusIndex == 0);
}

void drawScanQr() {
  blankPage();
  title("QR SCANNER", scanSubtitle());
  const auto p = qrClient.phase();
  if (p == qr_ble::Phase::Success) {
    drawScanQrSuccess();
    fullRefresh();
  } else if (p == qr_ble::Phase::Failed) {
    warningIcon(page, 270, 200);
    centeredFit(page, "ERROR", 320, 500, 3);
    centeredFit(page, scanErrorText(qrClient.error()), 400);
    centeredFit(page, "La camara no ha podido entregar el QR.", 470);
    buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
    buttonOn(page, kAction, "REINTENTAR", true, focusIndex == 1, Icon::reset);
    fullRefresh();
  } else {
    drawScanStatusInto(page, 20, 340);
    buttonOn(page, kAction, "CANCELAR", true, focusIndex == 0, Icon::x);
    fullRefresh();
    if (p == qr_ble::Phase::Receiving) {
      const uint16_t total = qrClient.totalChunks();
      const uint8_t pct =
          total ? static_cast<uint8_t>((qrClient.receivedChunks() * 100) / total)
                : 0;
      drawProgressBar(500, pct);
      lastQrProgress = pct;
    }
  }
}

void beginScanQr() {
  lastQrPhase = qr_ble::Phase::Idle;
  lastQrChunks = 0;
  lastQrProgress = 255;
  lastQrStatus = "";
  qrClient.clear();
  qrClient.start();
  screen = Screen::scan_qr;
  focusIndex = 0;
  drawScanQr();
}

void renderScanQrDynamic() {
  const auto p = qrClient.phase();
  if (p != lastQrPhase) {
    lastQrPhase = p;
    lastQrChunks = 0;
    lastQrProgress = 255;
    lastQrStatus = "";
    drawScanQr();
    return;
  }
  if (p == qr_ble::Phase::Receiving) {
    const uint16_t rcvd = qrClient.receivedChunks();
    if (rcvd != lastQrChunks) {
      lastQrChunks = rcvd;
      M5EPD_Canvas region(&M5.EPD);
      if (region.createCanvas(500, 160)) {
        region.fillCanvas(kWhite);
        drawScanStatusInto(region, 0, 0);
        region.pushCanvas(20, 340, UPDATE_MODE_DU4);
        region.deleteCanvas();
      }
      const uint16_t total = qrClient.totalChunks();
      const uint8_t pct =
          total ? static_cast<uint8_t>((rcvd * 100) / total) : 0;
      if (pct != lastQrProgress) {
        lastQrProgress = pct;
        drawProgressBar(500, pct);
      }
    }
  } else if (p == qr_ble::Phase::Waiting) {
    const String s = scanStatusLine();
    if (s != lastQrStatus) {
      lastQrStatus = s;
      M5EPD_Canvas region(&M5.EPD);
      if (region.createCanvas(500, 160)) {
        region.fillCanvas(kWhite);
        drawScanStatusInto(region, 0, 0);
        region.pushCanvas(20, 340, UPDATE_MODE_DU4);
        region.deleteCanvas();
      }
    }
  }
}

qr_wifi::QRWiFiServer wifiServer;
bool wifiResultShown = false;
Screen wifiModeReturnScreen = Screen::menu;
uint8_t wifiModeReturnFocus = 4;
psbt::ParsedTx parsedTx;
bool txIsPsbt = false;
bool txIsMultisig = false;
multisig::MultisigInfo txMsInfo;
Screen utxoReturnScreen = Screen::menu;
std::vector<uint8_t> signedTxBytes;
String signedTxHex;
String signedPsbtBase64;
std::vector<uint8_t> signedFinalizedPsbt;
bool txSigned = false;
QRCode signedTxQr;
uint8_t signedTxQrBuffer[4096] = {};
QRCode bbqrQr;
uint8_t bbqrQrBuffer[4096] = {};
size_t bbqrTotalParts = 1;
size_t bbqrBlockSize = 0;
uint16_t bbqrIndex = 0;
uint32_t bbqrLastFrameMs = 0;
bool bbqrSingle = true;

void drawWifiResult() {
  const std::vector<uint8_t>& d = wifiServer.data();
  textStyle(page, 2);
  page.setCursor(30, 175); page.printf("Format: %s", wifiServer.format().c_str());
  page.setCursor(30, 220); page.printf("Type: %s", wifiServer.type().c_str());
  page.setCursor(30, 265); page.printf("Size: %u bytes", static_cast<unsigned>(d.size()));
  page.setCursor(30, 310); page.println("Content:");
  page.drawRoundRect(20, 345, 500, 385, 8, kBlack);
  if (!d.empty() && isValidUtf8(d)) {
    drawWrappedText(page, scanPayloadText(d), 32, 358, 470, 22, 14);
  } else {
    textStyle(page, 2);
    page.setTextDatum(MC_DATUM);
    page.drawString("Binary payload / " + String(d.size()) + " bytes", 270, 520);
    page.setTextDatum(TL_DATUM);
  }
  buttonOn(page, kAction, "VOLVER", true, focusIndex == 0);
}

bool buildWifiQr() {
  memset(wifiQrBuffer, 0, sizeof(wifiQrBuffer));
  return qrcode_initText(&wifiQr, wifiQrBuffer, 4, ECC_LOW,
                         wifiServer.wifiQrText().c_str()) == 0;
}

uint8_t drawGroupedAddress(M5EPD_Canvas& canvas, const String& addr, int cx, int topY,
                           uint8_t size, int lineHeight) {
  textStyle(canvas, size);
  canvas.setTextDatum(TC_DATUM);
  String lines[8]; uint8_t lineCount = 0;
  for (unsigned position = 0; position < addr.length(); position += 4) {
    if (lineCount >= 8) break;
    if (lines[lineCount].length()) lines[lineCount] += ' ';
    lines[lineCount] += addr.substring(position, position + 4);
    if (((position / 4) + 1) % 4 == 0 && position + 4 < addr.length()) ++lineCount;
  }
  if (lines[lineCount].length()) ++lineCount;
  for (uint8_t i = 0; i < lineCount; ++i)
    canvas.drawString(lines[i], cx, topY + i * lineHeight);
  canvas.setTextDatum(TL_DATUM);
  return lineCount;
}

void drawTxInfo() {
  Serial.printf("[TX] fingerprintValid=%d txIsPsbt=%d words=%u/%u\n",
                fingerprintValid, txIsPsbt, wordCount, targetWords);
  title("TRANSACCION", "PSBT sin firmar - verifica con calma");
  textStyle(page, 2);
  int y = 158;
  page.setCursor(20, y);
  page.printf(lang::tr("Entradas: %u   Salidas: %u"),
              static_cast<unsigned>(parsedTx.inputs.size()),
              static_cast<unsigned>(parsedTx.outputs.size()));
  y += 34;
  if (parsedTx.inputsComplete) {
    page.setCursor(20, y);
    page.printf(lang::tr("Total a gastar: %s BTC"), psbt::formatSats(parsedTx.totalIn).c_str());
    y += 34;
  }
  page.setCursor(20, y);
  page.printf(lang::tr("Pago: %s BTC"), psbt::formatSats(parsedTx.totalPay).c_str());
  y += 34;
  page.setCursor(20, y);
  if (parsedTx.hasChangeInfo)
    page.printf(lang::tr("Cambio: %s BTC"), psbt::formatSats(parsedTx.totalChange).c_str());
  else
    page.print(lang::tr("Cambio: no marcado"));
  y += 34;
  if (parsedTx.inputsComplete) {
    page.setCursor(20, y);
    page.printf(lang::tr("Comision: %s BTC"), psbt::formatSats(parsedTx.fee).c_str());
    y += 34;
  }
  if (parsedTx.hasChangeInfo) {
    page.setCursor(20, y);
    page.print(lang::tr("Comprueba tu direccion de cambio"));
    y += 34;
  }
  y += 6;

  // Mostrar siempre las dos direcciones (pago y cambio).
  const size_t maxShow = 2;
  for (size_t i = 0; i < parsedTx.outputs.size() && i < maxShow; ++i) {
    const auto& o = parsedTx.outputs[i];
    if (y > 800) break;
    const String addr = o.address.length() ? o.address : lang::tr("direccion no estandar");
    const uint8_t addrLines = addr.length() > 64 ? 4 : (addr.length() + 15) / 16;

    const String label = o.isChange ? lang::tr("CAMBIO") : lang::tr("PAGO");
    const int boxH = 40 + addrLines * 46 + 16;
    page.drawRoundRect(20, y, 500, boxH, 8, kBlack);
    textStyle(page, 2);
    page.setCursor(34, y + 8);
    page.printf("%s: %s BTC", label.c_str(), psbt::formatSats(o.value).c_str());
    drawGroupedAddress(page, addr, 270, y + 42, 3, 46);
    y += boxH + 12;
  }
  if (parsedTx.outputs.size() > maxShow) {
    page.setCursor(20, y);
    page.printf(lang::tr("... y %u salidas mas"),
                static_cast<unsigned>(parsedTx.outputs.size() - maxShow));
  }
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
  buttonOn(page, kDetail, "DETALLE", true, focusIndex == 1, Icon::list);
  if (fingerprintValid)
    buttonOn(page, kFirmar, "FIRMAR", true, focusIndex == 2, Icon::key);
}

void drawUtxoDetail() {
  blankPage();
  title("UTXOS (ENTRADAS)", "De donde salen los fondos");
  textStyle(page, 2);
  int y = 160;
  const size_t maxShow = 5;
  for (size_t i = 0; i < parsedTx.inputs.size() && i < maxShow; ++i) {
    const auto& in = parsedTx.inputs[i];
    if (y > 780) break;
    page.setCursor(20, y);
    page.printf("#%u  %s BTC", static_cast<unsigned>(i + 1),
                psbt::formatSats(in.amount).c_str());
    y += 34;
    const String addr = in.address.length() ? in.address : lang::tr("direccion no disponible");
    const uint8_t lines = drawGroupedAddress(page, addr, 270, y, 2, 30);
    y += lines * 30 + 12;
  }
  if (parsedTx.inputs.size() > maxShow) {
    page.setCursor(20, y);
    page.printf(lang::tr("... y %u entradas mas"),
                static_cast<unsigned>(parsedTx.inputs.size() - maxShow));
  }
  buttonOn(page, kAction, "VOLVER", true, focusIndex == 0);
  fullRefresh();
}

String hexEncode(const std::vector<uint8_t>& data) {
  static const char hex[] = "0123456789abcdef";
  String out;
  out.reserve(data.size() * 2);
  for (uint8_t b : data) { out += hex[b >> 4]; out += hex[b & 0xF]; }
  return out;
}

void saveSignedTxToSd(const String& hex) {
  if (SD.cardType() == CARD_NONE) return;
  String path = "/TX-" + String(millis()) + ".hex";
  File f = SD.open(path, FILE_WRITE);
  if (f) {
    f.print(hex);
    f.close();
    Serial.printf("[TX] guardado en %s\n", path.c_str());
  }
}

void saveReceivedPsbt(const std::vector<uint8_t>& data) {
  if (SD.cardType() == CARD_NONE || data.empty()) return;
  String path = "/PSBT-" + String(millis()) + ".psbt";
  File f = SD.open(path, FILE_WRITE);
  if (f) {
    f.write(data.data(), data.size());
    f.close();
    Serial.printf("[PSBT] guardado en %s (%u bytes)\n", path.c_str(),
                  static_cast<unsigned>(data.size()));
  }
}

String base64Encode(const std::vector<uint8_t>& data) {
  size_t olen = 0;
  mbedtls_base64_encode(nullptr, 0, &olen, data.data(), data.size());
  std::vector<uint8_t> buf(olen + 1);
  if (mbedtls_base64_encode(buf.data(), buf.size(), &olen, data.data(), data.size()) != 0)
    return String();
  return String(reinterpret_cast<char*>(buf.data()));
}

bool buildSignedTxQr() {
  memset(signedTxQrBuffer, 0, sizeof(signedTxQrBuffer));
  static const uint16_t kByteCapL[] = {
      17, 32, 53, 78, 106, 134, 154, 192, 230, 271,
      321, 367, 425, 458, 520, 586, 644, 718, 792, 858,
      929, 1003, 1091, 1171, 1273, 1367, 1465, 1528, 1628, 1732,
      1840, 1952, 2068, 2188, 2303, 2431, 2563, 2699, 2809, 2953};
  const uint16_t len = signedTxHex.length();
  uint8_t version = 40;
  for (uint8_t v = 1; v <= 40; ++v) {
    if (len <= kByteCapL[v - 1]) { version = v; break; }
  }
  return qrcode_initText(&signedTxQr, signedTxQrBuffer, version, ECC_LOW,
                         signedTxHex.c_str()) == 0;
}

void drawSignedTx() {
  blankPage();
  if (!txSigned) {
    title("FIRMAR", "No se pudo firmar");
    warningIcon(page, 270, 200);
    centeredFit(page, "ERROR DE FIRMA", 320, 500, 3);
    centeredFit(page, "Comprueba la semilla y que el PSBT", 400);
    centeredFit(page, "tenga entradas P2WPKH con ruta.", 445);
  } else {
    title("TX FIRMADA", "Escanear con Sparrow para emitir");
    const int qrSize = signedTxQr.size;
    int module = kWidth / (qrSize + 8);  // 4 modulos de margen blanco a cada lado
    if (module < 2) module = 2;
    if (module > 8) module = 8;
    const int px = qrSize * module;
    const int quiet = module * 4;
    const int ox = (kWidth - px) / 2;
    const int oy = 175;
    page.fillRect(ox - quiet, oy - quiet, px + 2 * quiet, px + 2 * quiet, kWhite);
    for (uint8_t yy = 0; yy < signedTxQr.size; ++yy)
      for (uint8_t xx = 0; xx < signedTxQr.size; ++xx)
        if (qrcode_getModule(&signedTxQr, xx, yy))
          page.fillRect(ox + xx * module, oy + yy * module, module, module, kBlack);
    textStyle(page, 1);
    page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("Transaccion firmada y guardada en la SD"), 270, oy + px + 20);
    page.drawString("(" + String(signedTxBytes.size()) + " bytes)", 270, oy + px + 40);
    page.setTextDatum(TL_DATUM);
  }
  buttonOn(page, kAction, "VOLVER", true, focusIndex == 0);
  fullRefresh();
}

void drawSignedMode() {
  blankPage();
  title("EMITIR", "Elige el metodo de salida");
  buttonOn(page, kMenu[0], "SPARROW (QR estatico)", true, focusIndex == 0, Icon::qr);
  buttonOn(page, kMenu[1], "BLUEWALLET (QR animado)", !txIsMultisig, focusIndex == 1, Icon::qr);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 2);
  fullRefresh();
}

void drawAnimatedQr() {
  String frame;
  if (bbqrSingle) {
    frame = signedPsbtBase64;  // PSBT en Base64 (cHNidP8...), lo que espera BlueWallet
  } else {
    frame = bbqr::makeFrame(signedFinalizedPsbt.data(), signedFinalizedPsbt.size(),
                            bbqr::kTypePsbt, static_cast<uint16_t>(bbqrTotalParts),
                            bbqrIndex, bbqrBlockSize);
  }
  Serial.println("[BBQR] frame:");
  Serial.println(frame.c_str());
  Serial.printf("[BBQR] length=%u parts=%u index=%u single=%d\n",
                static_cast<unsigned>(frame.length()),
                static_cast<unsigned>(bbqrTotalParts),
                static_cast<unsigned>(bbqrIndex), bbqrSingle);
  memset(bbqrQrBuffer, 0, sizeof(bbqrQrBuffer));
  static const uint16_t kByteCapL[] = {
      17, 32, 53, 78, 106, 134, 154, 192, 230, 271,
      321, 367, 425, 458, 520, 586, 644, 718, 792, 858,
      929, 1003, 1091, 1171, 1273, 1367, 1465, 1528, 1628, 1732,
      1840, 1952, 2068, 2188, 2303, 2431, 2563, 2699, 2809, 2953};
  uint8_t version = 40;
  for (uint8_t v = 1; v <= 40; ++v) {
    if (frame.length() <= kByteCapL[v - 1]) { version = v; break; }
  }
  const int qrRc = qrcode_initText(&bbqrQr, bbqrQrBuffer, version, ECC_LOW, frame.c_str());

  blankPage();
  title("BLUEWALLET", "Escanea el QR animado (BBQr)");
  const int qrSize = bbqrQr.size;
  int module = kWidth / (qrSize + 8);
  if (module < 2) module = 2;
  if (module > 8) module = 8;
  const int px = qrSize * module;
  const int quiet = module * 4;
  const int ox = (kWidth - px) / 2;
  const int oy = 160;
  Serial.printf("[QR] payload length=%u\n", static_cast<unsigned>(frame.length()));
  Serial.printf("[QR] matrix size=%u\n", static_cast<unsigned>(bbqrQr.size));
  Serial.printf("[QR] module pixels=%d\n", module);
  Serial.printf("[QR] rendered pixels=%d\n", px);
  Serial.printf("[QR] quiet zone=4\n");
  Serial.printf("[QR] origin=%d,%d\n", ox - quiet, oy - quiet);
  Serial.printf("[QR] ECC=L rc=%d version=%u\n", qrRc, version);
  page.fillRect(ox - quiet, oy - quiet, px + 2 * quiet, px + 2 * quiet, kWhite);
  for (uint8_t yy = 0; yy < bbqrQr.size; ++yy)
    for (uint8_t xx = 0; xx < bbqrQr.size; ++xx)
      if (qrcode_getModule(&bbqrQr, xx, yy))
        page.fillRect(ox + xx * module, oy + yy * module, module, module, kBlack);
  textStyle(page, 3);
  page.setTextDatum(MC_DATUM);
  page.drawString(String(static_cast<uint32_t>(bbqrIndex) + 1) + " / " +
                  String(static_cast<uint32_t>(bbqrTotalParts)), 270, oy + px + 40);
  textStyle(page, 2);
  page.drawString(lang::tr("Manten el movil quieto"), 270, oy + px + 80);
  page.setTextDatum(TL_DATUM);
  buttonOn(page, kAction, "VOLVER", true, focusIndex == 0);
  fullRefresh();
}

void beginAnimatedQr() {
  if (!txSigned || signedFinalizedPsbt.empty()) {
    screen = Screen::signed_mode; focusIndex = 0; drawScreen();
    return;
  }
  const bbqr::Layout layout = bbqr::calculateLayout(signedFinalizedPsbt.size(),
                                                     bbqr::kPreferredBlockSize);
  bbqrTotalParts = layout.totalParts;
  bbqrBlockSize = layout.blockSize;
  bbqrSingle = (bbqrTotalParts == 1);
  bbqrIndex = 0;
  bbqrLastFrameMs = millis();
  screen = Screen::animated_qr;
  focusIndex = 0;
  drawAnimatedQr();
}

void buildMultisigSeedCandidates(std::vector<multisig::SeedCandidate>& out) {
  out.clear();
  // Semilla activa (con su passphrase si la hay).
  if (fingerprintValid) {
    multisig::SeedCandidate c = {words, targetWords,
                                 passphraseActive ? activePassphrase : ""};
    out.push_back(c);
  }
  // Resto de semillas cargadas en RAM/vault (sin passphrase).
  for (uint8_t i = 0; i < loadedSeedCount; ++i) {
    if (!loadedSeeds[i].used) continue;
    bool dup = false;
    if (activeLoadedSeed == static_cast<int8_t>(i)) dup = true;
    for (const auto& c : out)
      if (c.indices == loadedSeeds[i].indices && c.count == loadedSeeds[i].count)
        dup = true;
    if (dup) continue;
    multisig::SeedCandidate c = {loadedSeeds[i].indices, loadedSeeds[i].count, ""};
    out.push_back(c);
  }
}

void drawMultisigConfirm() {
  blankPage();
  const uint8_t m = txMsInfo.m, n = txMsInfo.n;
  const String sub = String(lang::tr("Politica")) + ": " + String(m) + " " +
                     lang::tr("de") + " " + String(n) + "  P2WSH";
  title("MULTISIG TRANSACTION", sub.c_str());

  std::vector<multisig::SeedCandidate> seeds;
  buildMultisigSeedCandidates(seeds);

  // Firmas existentes, claves del Vault disponibles y signers.
  uint8_t existingSigs = 0, vaultKeys = 0;
  String signerLines[multisig::kMaxKeys];
  uint8_t signerCount = 0;
  if (!parsedTx.inputs.empty()) {
    const auto& in = parsedTx.inputs[0];
    multisig::MultisigScript ms;
    if (multisig::parseSortedMulti(in.witnessScript, in.witnessScriptLen, ms)) {
      int8_t matchByKey[multisig::kMaxKeys];
      multisig::matchSigners(in, ms, seeds, matchByKey);
      for (uint8_t k = 0; k < ms.n && signerCount < multisig::kMaxKeys; ++k) {
        const uint8_t* s; size_t sl;
        const bool hasSig = multisig::findSig(in.partialSigs, ms.keys[k], &s, &sl);
        const bool inVault = matchByKey[k] >= 0;
        if (hasSig) existingSigs++;
        else if (inVault) vaultKeys++;
        String fpr = "????????";
        for (const auto& si : in.signers)
          if (memcmp(si.pub, ms.keys[k], 33) == 0) {
            char buf[9] = {};
            snprintf(buf, sizeof(buf), "%02X%02X%02X%02X",
                     si.fpr[0], si.fpr[1], si.fpr[2], si.fpr[3]);
            fpr = buf;
            break;
          }
        const char* mark = hasSig ? "=" : inVault ? ">" : ".";
        signerLines[signerCount++] = String(mark) + " " + fpr +
            (hasSig ? " (" + String(lang::tr("FIRMADO")) + ")"
                    : inVault ? " (" + String(lang::tr("VAULT")) + ")"
                              : " (" + String(lang::tr("EXTERNO")) + ")");
      }
    }
  }

  textStyle(page, 2);
  int y = 158;
  page.setCursor(20, y);
  page.printf(lang::tr("Entradas: %u   Salidas: %u"),
              static_cast<unsigned>(parsedTx.inputs.size()),
              static_cast<unsigned>(parsedTx.outputs.size()));
  y += 34;
  page.setCursor(20, y);
  page.printf(lang::tr("Pago: %s BTC"), psbt::formatSats(parsedTx.totalPay).c_str());
  y += 34;
  page.setCursor(20, y);
  if (parsedTx.hasChangeInfo)
    page.printf(lang::tr("Cambio: %s BTC"), psbt::formatSats(parsedTx.totalChange).c_str());
  else
    page.print(lang::tr("Cambio: no marcado"));
  y += 34;
  if (parsedTx.inputsComplete) {
    page.setCursor(20, y);
    page.printf(lang::tr("Comision: %s BTC"), psbt::formatSats(parsedTx.fee).c_str());
    y += 34;
  }
  // Informacion multisig.
  page.setCursor(20, y);
  page.printf(lang::tr("Firmas: %u/%u"), existingSigs, m);
  page.setCursor(240, y);
  page.print(String(lang::tr("Vault:")) + " " + String(vaultKeys));
  y += 32;
  textStyle(page, 2);
  for (uint8_t i = 0; i < signerCount; ++i) {
    page.setCursor(20, y);
    page.print(signerLines[i]);
    y += 30;
  }
  y += 4;

  // Direcciones (PAGO/CAMBIO) en recuadro, como la pantalla single-sig.
  const size_t maxShow = 2;
  size_t shown = 0;
  for (size_t i = 0; i < parsedTx.outputs.size() && shown < maxShow; ++i) {
    const auto& o = parsedTx.outputs[i];
    if (y > 760) break;
    const String addr = o.address.length() ? o.address : lang::tr("direccion no estandar");
    const uint8_t addrLines = addr.length() > 64 ? 4 : (addr.length() + 15) / 16;
    const String label = o.isChange ? lang::tr("CAMBIO") : lang::tr("PAGO");
    const int boxH = 40 + addrLines * 46 + 16;
    page.drawRoundRect(20, y, 500, boxH, 8, kBlack);
    textStyle(page, 2);
    page.setCursor(34, y + 8);
    page.printf("%s: %s BTC", label.c_str(), psbt::formatSats(o.value).c_str());
    drawGroupedAddress(page, addr, 270, y + 42, 3, 46);
    y += boxH + 10;
    shown++;
  }
  if (parsedTx.outputs.size() > shown) {
    page.setCursor(20, y);
    page.printf(lang::tr("... y %u salidas mas"),
                static_cast<unsigned>(parsedTx.outputs.size() - shown));
  }

  const bool enough = (existingSigs + vaultKeys) >= m;
  buttonOn(page, kBack, lang::tr("CANCELAR"), true, focusIndex == 0);
  String signLabel = String(lang::tr("FIRMAR CON ")) + String(vaultKeys) + " " + lang::tr("claves");
  buttonOn(page, kFirmar, signLabel.c_str(), enough, focusIndex == 1, Icon::key);
  fullRefresh();
}

void drawSigningFeedback() {
  blankPage();
  title("FIRMANDO", "Firmando la transaccion...");
  textStyle(page, 3);
  page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("Calculando firmas ECDSA."), kWidth / 2, 380);
  textStyle(page, 2);
  page.drawString(lang::tr("Puede tardar unos segundos."), kWidth / 2, 450);
  page.setTextDatum(TL_DATUM);
  fullRefresh(UPDATE_MODE_DU4);
}

void beginMultisigSign() {
  drawSigningFeedback();
  std::vector<multisig::SeedCandidate> seeds;
  buildMultisigSeedCandidates(seeds);
  multisig::SignResult res = multisig::signMultisig(parsedTx, seeds);

  txSigned = false;
  signedTxHex = "";
  signedPsbtBase64 = "";
  signedTxBytes.clear();
  signedFinalizedPsbt.clear();

  if (res.finalized) {
    signedTxBytes = res.rawTx;
    signedTxHex = hexEncode(signedTxBytes);
    signedFinalizedPsbt = res.finalizedPsbt;  // (vacio: no se reconstruye el final)
    txSigned = true;
    saveSignedTxToSd(signedTxHex);
    Serial.printf("[SIGNED] %s\n", signedTxHex.c_str());
    if (signedTxHex.length()) buildSignedTxQr();
    screen = Screen::signed_mode; focusIndex = 0; drawSignedMode();
  } else {
    // PSBT parcialmente firmada: exportar por QR/BBQr.
    signedFinalizedPsbt = res.partialPsbt;
    signedPsbtBase64 = base64Encode(res.partialPsbt);
    txSigned = false;
    // Reutiliza la pantalla de emision (SPARROW/BLUEWALLET) con la PSBT parcial.
    screen = Screen::signed_mode; focusIndex = 0; drawSignedMode();
  }
}

void beginSignTx() {
  if (txIsMultisig) { beginMultisigSign(); return; }
  drawSigningFeedback();
  txSigned = false;
  signedTxHex = "";
  signedPsbtBase64 = "";
  signedTxBytes.clear();
  std::vector<uint8_t> finalizedPsbt;
  if (tx_sign::signSegwitP2wpkh(parsedTx, words, targetWords,
        passphraseActive ? activePassphrase : "", signedTxBytes, &finalizedPsbt)) {
    signedTxHex = hexEncode(signedTxBytes);
    signedPsbtBase64 = base64Encode(finalizedPsbt);
    signedFinalizedPsbt = finalizedPsbt;
    txSigned = true;
    saveSignedTxToSd(signedTxHex);
    Serial.printf("[SIGNED] %s\n", signedTxHex.c_str());
    if (signedPsbtBase64.length()) buildSignedTxQr();
  }
  screen = Screen::signed_mode;
  focusIndex = 0;
  drawSignedMode();
}

void drawScreensaver(bool hardLock) {
  page.fillCanvas(kWhite);
  const int cx = kWidth / 2;

  textStyle(page, 2);
  page.setTextDatum(MC_DATUM);
  page.drawString("M5Paper Seed Workstation", cx, 150);

  page.fillCircle(cx, 400, 125, kBlack);
  textStyle(page, 7, kWhite, kBlack);
  page.setTextDatum(MC_DATUM);
  page.drawString("B", cx, 400);

  if (hardLock) {
    textStyle(page, 4);
    page.setTextDatum(MC_DATUM);
    page.drawString(lang::tr("BLOQUEADO"), cx, 590);
  }

  textStyle(page, 2);
  page.setTextDatum(MC_DATUM);
  page.drawString(lang::tr("Pulsa o toca para desbloquear"), cx, hardLock ? 655 : 590);

  textStyle(page, 1);
  page.setTextDatum(MC_DATUM);
  page.drawString(String("Firmware: ") + kVersion + "   " +
                  String(M5.getBatteryVoltage()) + " mV", cx, 900);
  page.setTextDatum(TL_DATUM);
  fullRefresh();
}

void lockDevice() {
  if (sessionUnlocked) lockSessionVault();
  else if (fingerprintValid) discardActiveSeed();
  screensaverHardLock = true;
  screen = Screen::locked;
  focusIndex = 0;
  drawScreensaver(true);
}

void enterScreensaver() {
  screensaverReturn = screen;
  screensaverHardLock = false;
  screen = Screen::screensaver;
  focusIndex = 0;
  drawScreensaver(false);
}

void drawTxReview() {
  blankPage();
  drawTxInfo();
  fullRefresh();
}

std::vector<uint8_t> serialBuf;
bool serialWaitingPayload = false;
uint32_t serialExpectedLen = 0;
String serialShaHex;

bool isBase64Char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

void afterPsbtParsed(bool fromSerial) {
  txIsMultisig = multisig::detect(parsedTx, txMsInfo);
  if (txIsMultisig) {
    Serial.printf("[MULTISIG] detected P2WSH policy=%u-of-%u\n", txMsInfo.m, txMsInfo.n);
    screen = Screen::multisig_confirm;
    focusIndex = 0;
    drawMultisigConfirm();
  } else if (fromSerial) {
    screen = Screen::tx_review;
    focusIndex = 0;
    drawTxReview();
  }
}

void loadPsbtFromFile(const char* path) {
  File f = SD.open(path, FILE_READ);
  if (!f) { showToast("No se pudo abrir"); return; }
  std::vector<uint8_t> data(f.size());
  f.read(data.data(), data.size());
  f.close();
  txIsPsbt = psbt::tryParsePsbt(data, parsedTx);
  if (txIsPsbt) {
    afterPsbtParsed(true);
  } else {
    showToast("PSBT no valido");
    screen = Screen::tx_history; focusIndex = 0; drawTxHistory();
  }
}

void processSerialText(const String& payload) {
  std::vector<uint8_t> data(payload.length());
  memcpy(data.data(), payload.c_str(), payload.length());
  if (psbt::tryParsePsbt(data, parsedTx)) {
    txIsPsbt = true;
    saveReceivedPsbt(data);
    Serial.printf("[SERIAL] PSBT cargado (%u chars)\n", static_cast<unsigned>(payload.length()));
    afterPsbtParsed(true);
    showToast("PSBT recibido por serial");
  } else {
    Serial.println("[SERIAL] error: no es un PSBT valido (base64/hex/binario)");
    showToast("Serial: no es un PSBT valido");
  }
}

void processSerialBinary(const std::vector<uint8_t>& payload, const String& shaHex) {
  uint8_t digest[32] = {};
  mbedtls_sha256_ret(payload.data(), payload.size(), digest, 0);
  static const char hexc[] = "0123456789abcdef";
  String computed;
  computed.reserve(64);
  for (int i = 0; i < 32; ++i) {
    computed += hexc[digest[i] >> 4];
    computed += hexc[digest[i] & 0xF];
  }
  if (!computed.equalsIgnoreCase(shaHex)) {
    Serial.printf("[SERIAL] SHA256 NO coincide (esperado %s, calculado %s)\n",
                  shaHex.c_str(), computed.c_str());
    showToast("Serial: SHA256 no coincide");
    return;
  }
  Serial.printf("[SERIAL] PSBT binario (%u bytes) SHA256 OK\n",
                static_cast<unsigned>(payload.size()));
  if (psbt::tryParsePsbt(payload, parsedTx)) {
    txIsPsbt = true;
    saveReceivedPsbt(payload);
    afterPsbtParsed(true);
    showToast("PSBT recibido por serial");
  } else {
    Serial.println("[SERIAL] no es un PSBT valido");
    showToast("Serial: no es un PSBT valido");
  }
}

void checkSerialCommand() {
  while (Serial.available()) serialBuf.push_back(static_cast<uint8_t>(Serial.read()));
  if (serialBuf.size() > 20000) serialBuf.erase(serialBuf.begin(), serialBuf.begin() + 10000);

  // Esperando el payload binario tras haber recibido la cabecera.
  if (serialWaitingPayload) {
    if (serialBuf.size() >= serialExpectedLen) {
      std::vector<uint8_t> payload(serialBuf.begin(), serialBuf.begin() + serialExpectedLen);
      serialBuf.erase(serialBuf.begin(), serialBuf.begin() + serialExpectedLen);
      serialWaitingPayload = false;
      processSerialBinary(payload, serialShaHex);
    } else {
      return;
    }
  }

  // Protocolo binario del script: "M5PSBT <len> <sha256>\n" + payload binario.
  static const char kHdr[] = "M5PSBT ";
  const size_t hlen = 7;
  for (size_t i = 0; i + hlen <= serialBuf.size(); ++i) {
    if (memcmp(&serialBuf[i], kHdr, hlen) != 0) continue;
    size_t j = i + hlen;
    String lenStr;
    while (j < serialBuf.size() && serialBuf[j] >= '0' && serialBuf[j] <= '9') {
      lenStr += static_cast<char>(serialBuf[j]); ++j;
    }
    if (j < serialBuf.size() && serialBuf[j] == ' ') ++j;
    String sha;
    while (j < serialBuf.size() && serialBuf[j] != '\n' && serialBuf[j] != '\r') {
      sha += static_cast<char>(serialBuf[j]); ++j;
    }
    if (j < serialBuf.size() && (serialBuf[j] == '\n' || serialBuf[j] == '\r')) ++j;
    const uint32_t len = lenStr.toInt();
    if (len == 0) { serialBuf.erase(serialBuf.begin(), serialBuf.begin() + j); break; }
    serialBuf.erase(serialBuf.begin(), serialBuf.begin() + j);
    serialExpectedLen = len;
    serialShaHex = sha;
    serialWaitingPayload = true;
    Serial.println("READY");
    Serial.flush();
    break;
  }
  if (serialWaitingPayload) return;

  // Comando de texto: incommit-transaction:/psbt:/firmar: <base64/hex>.
  static const char* kCmds[] = {"incommit-transaction:", "psbt:", "firmar:"};
  for (size_t i = 0; i < serialBuf.size(); ++i) {
    int cmdLen = -1;
    for (int c = 0; c < 3; ++c) {
      const size_t l = strlen(kCmds[c]);
      if (i + l <= serialBuf.size() && memcmp(&serialBuf[i], kCmds[c], l) == 0) {
        cmdLen = static_cast<int>(l); break;
      }
    }
    if (cmdLen < 0) continue;
    String payload;
    size_t k = i + cmdLen;
    while (k < serialBuf.size()) {
      const char ch = static_cast<char>(serialBuf[k]);
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '"') {
        if (payload.length() == 0) { ++k; continue; }
        break;
      }
      if (isBase64Char(ch)) { payload += ch; ++k; }
      else break;
    }
    serialBuf.erase(serialBuf.begin(), serialBuf.begin() + k);
    if (payload.length() >= 20) {
      Serial.printf("[SERIAL] comando texto (%u chars)\n", static_cast<unsigned>(payload.length()));
      processSerialText(payload);
    } else {
      Serial.println("[SERIAL] payload vacio o demasiado corto");
    }
    break;
  }
}

const char* wifiModeTitle(qr_wifi::Mode mode);
const char* wifiModeHint(qr_wifi::Mode mode);

void drawWifiReceive() {
  blankPage();
  const auto p = wifiServer.phase();
  const qr_wifi::Mode mode = wifiServer.mode();
  if (p == qr_wifi::Phase::Received) {
    if (mode == qr_wifi::Mode::kSeedText) {
      title("SEMILLA NO VALIDA", "No se pudo importar la semilla");
      warningIcon(page, 270, 200);
      centeredFit(page, "ERROR", 320, 500, 3);
      centeredFit(page, "Revisa las palabras y que sean 12 o 24.", 400);
      buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
      buttonOn(page, kAction, "REINTENTAR", true, focusIndex == 1, Icon::reset);
    } else if (txIsPsbt) {
      drawTxInfo();
    } else {
      title("RECIBIDO", "Datos recibidos por WiFi");
      drawWifiResult();
    }
  } else if (p == qr_wifi::Phase::Failed) {
    title("RECIBIR POR WIFI", "No se pudo activar el punto de acceso");
    warningIcon(page, 270, 200);
    centeredFit(page, "ERROR", 320, 500, 3);
    centeredFit(page, "No se pudo crear la red WiFi.", 400);
    buttonOn(page, kBack, "VOLVER", true, focusIndex == 0);
    buttonOn(page, kAction, "REINTENTAR", true, focusIndex == 1, Icon::reset);
  } else {
    title("RECIBIR POR WIFI", wifiModeHint(mode));
    const int module = 8;
    const int px = wifiQr.size * module;
    const int ox = (kWidth - px) / 2;
    const int oy = 165;
    page.fillRect(ox - 15, oy - 15, px + 30, px + 30, kWhite);
    for (uint8_t y = 0; y < wifiQr.size; ++y)
      for (uint8_t x = 0; x < wifiQr.size; ++x)
        if (qrcode_getModule(&wifiQr, x, y))
          page.fillRect(ox + x * module, oy + y * module, module, module, kBlack);
    const int ty = oy + px + 25;
    textStyle(page, 2); page.setTextDatum(MC_DATUM);
    page.drawString(String("SSID: ") + qr_wifi::kApSsid, 270, ty);
    page.drawString(String(lang::tr("Clave: ")) + wifiServer.password(), 270, ty + 40);
    page.drawString("URL: http://192.168.4.1", 270, ty + 80);
    textStyle(page, 1);
    page.drawString(String(lang::tr("Modo: ")) + lang::tr(wifiModeTitle(mode)), 270, ty + 130);
    page.setTextDatum(TL_DATUM);
    buttonOn(page, kAction, "CANCELAR", true, focusIndex == 0, Icon::x);
  }
  fullRefresh();
}

const char* wifiModeTitle(qr_wifi::Mode mode) {
  return mode == qr_wifi::Mode::kFile ? "Subir fichero PSBT" :
         mode == qr_wifi::Mode::kTxText ? "Pegar transaccion" : "Pegar semilla BIP39";
}

const char* wifiModeHint(qr_wifi::Mode mode) {
  return mode == qr_wifi::Mode::kFile
             ? "Conectate y sube el fichero PSBT desde la web"
         : mode == qr_wifi::Mode::kTxText
             ? "Conectate y pega la transaccion en la web"
             : "Conectate y pega la semilla BIP39 en la web";
}

void openWifiMode() {
  wifiModeReturnScreen = screen;
  wifiModeReturnFocus = focusIndex;
  screen = Screen::wifi_mode;
  focusIndex = 0;
  drawScreen();
}

void returnFromWifiReceive() {
  wifiServer.clear();
  screen = wifiModeReturnScreen;
  focusIndex = wifiModeReturnFocus;
  drawScreen();
}

void drawWifiMode() {
  blankPage();
  title("RECIBIR POR WIFI", "Elige que vas a enviar");
  buttonOn(page, kMenu[0], "SUBIR FICHERO (PSBT)", fingerprintValid, focusIndex == 0, Icon::wifi);
  buttonOn(page, kMenu[1], "PEGAR TRANSACCION (PSBT)", fingerprintValid, focusIndex == 1, Icon::wifi);
  buttonOn(page, kMenu[2], "PEGAR SEMILLA BIP39", true, focusIndex == 2, Icon::key);
  buttonOn(page, kBack, "VOLVER", true, focusIndex == 3);
  fullRefresh();
}

void beginWifiReceive(qr_wifi::Mode mode) {
  wifiResultShown = false;
  txIsPsbt = false;
  wifiServer.clear();
  wifiServer.start(mode);
  buildWifiQr();
  screen = Screen::wifi_receive;
  focusIndex = 0;
  drawWifiReceive();
}

bool loadSeedText(const std::vector<uint8_t>& data) {
  if (data.empty() || !isValidUtf8(data)) return false;
  String text = scanPayloadText(data);
  text.trim();
  text.toLowerCase();

  uint16_t indices[24] = {};
  size_t count = 0;
  size_t pos = 0;
  const size_t len = text.length();
  while (pos < len && count < 24) {
    while (pos < len && (text[pos] == ' ' || text[pos] == '\t' ||
                         text[pos] == '\n' || text[pos] == '\r')) ++pos;
    if (pos >= len) break;
    const size_t start = pos;
    while (pos < len && text[pos] != ' ' && text[pos] != '\t' &&
           text[pos] != '\n' && text[pos] != '\r') ++pos;
    const String w = text.substring(start, pos);
    const uint16_t idx = bip39::find_exact(w);
    if (idx == bip39::kInvalidWord) return false;
    indices[count++] = idx;
  }
  if (pos < len) return false;
  if (count != 12 && count != 24) return false;
  if (!bip39::checksum_valid(indices, count)) return false;

  if (fingerprintValid) discardActiveSeed();
  resetPhrase(static_cast<uint8_t>(count));
  memcpy(words, indices, count * sizeof(uint16_t));
  wordCount = static_cast<uint8_t>(count);
  targetWords = static_cast<uint8_t>(count);
  prefix = "";
  editingWord = -1;
  const bool ok = updateFingerprint();
  encrypted_seed_store::wipe(indices, sizeof(indices));
  return ok;
}

const char* timeoutLabel(uint32_t ms) {
  if (ms == device_settings::kTimeoutNone) return lang::tr("Nunca");
  if (ms == device_settings::kTimeout1m) return lang::tr("1 minuto");
  if (ms == device_settings::kTimeout3m) return lang::tr("3 minutos");
  if (ms == device_settings::kTimeout5m) return lang::tr("5 minutos");
  return lang::tr("10 minutos");
}

const char* profileLabel(uint8_t p) {
  switch (p) {
    case 0: return lang::tr("BIP44 (P2PKH)");
    case 1: return lang::tr("BIP49 (P2SH)");
    default: return lang::tr("BIP84 (SegWit)");
  }
}

const char* cleanLabel(uint32_t ms) {
  if (ms == device_settings::kCleanNone) return lang::tr("Nunca");
  if (ms == device_settings::kClean10m) return lang::tr("10 minutos");
  if (ms == device_settings::kClean30m) return lang::tr("30 minutos");
  return lang::tr("60 minutos");
}

void saveSettingsNow() {
  if (device_settings::save(gSettings)) showToast("Guardado en la SD");
  else showToast("No se pudo guardar la configuracion");
}

String settingsLangLabel() {
  return String(lang::tr("Idioma")) + ": " +
      (gSettings.language == 1 ? lang::tr("Espanol") : lang::tr("Ingles"));
}

String settingsTimeoutLabel() {
  return String(lang::tr("Tiempo de bloqueo")) + ": " +
      timeoutLabel(gSettings.lockTimeoutMs);
}

String settingsDerivLabel() {
  return String(lang::tr("Derivacion por defecto")) + ": " +
      profileLabel(gSettings.defaultProfile);
}

String settingsCleanLabel() {
  return String(lang::tr("Limpieza de seed")) + ": " +
      cleanLabel(gSettings.seedCleanTimeoutMs);
}

void drawSettings() {
  blankPage();
  title("AJUSTES", "Configuracion del dispositivo");
  buttonOn(page, kMenu[0], settingsLangLabel().c_str(), true, focusIndex == 0, Icon::none);
  buttonOn(page, kMenu[1], settingsTimeoutLabel().c_str(), true, focusIndex == 1, Icon::lock);
  buttonOn(page, kMenu[2], settingsCleanLabel().c_str(), true, focusIndex == 2, Icon::trash);
  buttonOn(page, kMenu[3], settingsDerivLabel().c_str(), true, focusIndex == 3, Icon::key);
  buttonOn(page, kMenu[4], lang::tr("Estado de la radio"), true, focusIndex == 4, Icon::wifi);
  buttonOn(page, kBack, lang::tr("VOLVER"), true, focusIndex == 5);
  fullRefresh();
}

void drawSettingsLang() {
  blankPage();
  title(lang::tr("Idioma"), lang::tr("Elige el idioma de la interfaz"));
  buttonOn(page, kMenu[0], lang::tr("Ingles"), true,
           gSettings.language == 0 && focusIndex == 0, Icon::none);
  buttonOn(page, kMenu[1], lang::tr("Espanol"), true,
           gSettings.language == 1 && focusIndex == 1, Icon::none);
  buttonOn(page, kBack, lang::tr("VOLVER"), true, focusIndex == 2);
  fullRefresh();
}

void drawSettingsTimeout() {
  blankPage();
  title(lang::tr("Tiempo de bloqueo"), lang::tr("Bloqueo automatico por inactividad"));
  for (uint8_t i = 0; i < device_settings::kTimeoutOptionCount; ++i) {
    const uint32_t ms = device_settings::kTimeoutOptions[i];
    buttonOn(page, kMenu[i], timeoutLabel(ms), true,
             gSettings.lockTimeoutMs == ms && focusIndex == i, Icon::lock);
  }
  buttonOn(page, kBack, lang::tr("VOLVER"), true,
           focusIndex == device_settings::kTimeoutOptionCount);
  fullRefresh();
}

void drawSettingsClean() {
  blankPage();
  title(lang::tr("Limpieza de seed"), lang::tr("Borra la semilla de RAM por inactividad"));
  for (uint8_t i = 0; i < device_settings::kCleanOptionCount; ++i) {
    const uint32_t ms = device_settings::kCleanOptions[i];
    buttonOn(page, kMenu[i], cleanLabel(ms), true,
             gSettings.seedCleanTimeoutMs == ms && focusIndex == i, Icon::trash);
  }
  buttonOn(page, kBack, lang::tr("VOLVER"), true,
           focusIndex == device_settings::kCleanOptionCount);
  fullRefresh();
}

void drawSettingsDerivation() {
  blankPage();
  title(lang::tr("Derivacion por defecto"), lang::tr("Tipo de script"));
  for (uint8_t i = 0; i < kPublicProfileCount; ++i) {
    buttonOn(page, kMenu[i], profileLabel(i), true,
             gSettings.defaultProfile == i && focusIndex == i, Icon::key);
  }
  buttonOn(page, kBack, lang::tr("VOLVER"), true, focusIndex == kPublicProfileCount);
  fullRefresh();
}

void drawSettingsRadio() {
  blankPage();
  title(lang::tr("Estado de la radio"), lang::tr("Radios y energia"));
  const bool bleOn = scanQrActive();
  const auto wp = wifiServer.phase();
  const bool wifiOn = wp == qr_wifi::Phase::Starting || wp == qr_wifi::Phase::Waiting ||
                      wp == qr_wifi::Phase::Received;
  const bool sdOk = SD.cardType() != CARD_NONE;

  textStyle(page, 2);
  int y = 170;
  page.setCursor(20, y);
  page.print(lang::tr("Bluetooth"));
  page.setCursor(300, y);
  page.print(bleOn ? lang::tr("ESCANEANDO") : lang::tr("APAGADO"));
  y += 40;
  page.setCursor(20, y);
  page.print(lang::tr("WiFi"));
  page.setCursor(300, y);
  page.print(wifiOn ? lang::tr("PUNTO DE ACCESO") : lang::tr("APAGADO"));
  y += 40;
  page.setCursor(20, y);
  page.print(lang::tr("microSD"));
  page.setCursor(300, y);
  page.print(sdOk ? lang::tr("OK") : lang::tr("NO DETECTADA"));
  y += 40;
  page.setCursor(20, y);
  page.print(lang::tr("Bateria"));
  page.setCursor(300, y);
  page.print(String(M5.getBatteryVoltage()) + " mV");
  buttonOn(page, kBack, lang::tr("VOLVER"), true, focusIndex == 0);
  fullRefresh();
}

void drawScreen() {
  switch (screen) {
    case Screen::menu: drawMenu(); break;
    case Screen::active_seed: drawActiveSeed(); break;
    case Screen::seed_switcher: drawSeedSwitcher(); break;
    case Screen::passphrase_input: drawPassphraseInput(); break;
    case Screen::backup_seed: drawBackupSeed(); break;
    case Screen::vault_actions: drawVaultActions(); break;
    case Screen::length: drawLength(); break;
    case Screen::keyboard: drawKeyboard(); break;
    case Screen::review: drawReview(); break;
    case Screen::plain_qr: drawPlainQR(); break;
    case Screen::seedqr: drawSeedQR(); break;
    case Screen::public_key: drawPublicKey(); break;
    case Screen::public_key_qr: drawPublicKeyQr(); break;
    case Screen::entropy_length: drawEntropyLength(); break;
    case Screen::entropy: drawEntropy(); break;
    case Screen::dice: drawDice(); break;
    case Screen::security_warning: drawSecurityWarning(); break;
    case Screen::vault_password: drawVaultPassword(); break;
    case Screen::vault_result: drawVaultResult(); break;
    case Screen::vault_label: drawVaultLabel(); break;
    case Screen::vault_list: drawVaultList(); break;
    case Screen::vault_unlock: drawVaultUnlock(); break;
    case Screen::vault_loaded: drawVaultLoaded(); break;
    case Screen::session_menu: drawSessionMenu(); break;
    case Screen::session_meta_list: drawSessionMetaList(); break;
    case Screen::session_seed_list: drawSessionSeedList(); break;
    case Screen::delete_confirm: drawDeleteConfirm(); break;
    case Screen::address_explorer: drawAddressExplorer(); break;
    case Screen::address_index_input: drawAddressIndexInput(); break;
    case Screen::address_qr: drawAddressQr(); break;
    case Screen::discard_confirm: drawDiscardConfirm(); break;
    case Screen::unlock_confirm: drawUnlockConfirm(); break;
    case Screen::session_lock_warning: drawSessionLockWarning(); break;
    case Screen::help: drawHelp(); break;
    case Screen::diagnostics: drawDiagnostics(); break;
    case Screen::scan_qr: drawScanQr(); break;
    case Screen::wifi_receive: drawWifiReceive(); break;
    case Screen::wifi_mode: drawWifiMode(); break;
    case Screen::signed_tx: drawSignedTx(); break;
    case Screen::locked: drawScreensaver(true); break;
    case Screen::screensaver: drawScreensaver(false); break;
    case Screen::tx_review: drawTxReview(); break;
    case Screen::utxo_detail: drawUtxoDetail(); break;
    case Screen::signed_mode: drawSignedMode(); break;
    case Screen::animated_qr: drawAnimatedQr(); break;
    case Screen::settings: drawSettings(); break;
    case Screen::settings_lang: drawSettingsLang(); break;
    case Screen::settings_timeout: drawSettingsTimeout(); break;
    case Screen::settings_clean: drawSettingsClean(); break;
    case Screen::settings_derivation: drawSettingsDerivation(); break;
    case Screen::settings_radio: drawSettingsRadio(); break;
    case Screen::multisig_confirm: drawMultisigConfirm(); break;
    case Screen::tx_history: drawTxHistory(); break;
  }
}

void updateFocusButton(uint8_t index) {
  switch (screen) {
    case Screen::menu: {
      static const Icon kMenuIcons[] = {Icon::keyboard, Icon::draw, Icon::lock,
                                        Icon::wifi, Icon::list, Icon::wrench,
                                        Icon::lock};
      updateButton(kMenu[index], menuLabel(index), menuEnabled(index),
                   index == focusIndex, kMenuIcons[index]); break;
    }
    case Screen::active_seed: {
      static const Icon kActiveIcons[] = {Icon::key, Icon::shield, Icon::lock,
                                          Icon::eye, Icon::trash};
      if (index == 5) {
        updateButton(kActiveMenu[index], "RECIBIR POR WIFI", true,
                     index == focusIndex, Icon::wifi);
      } else if (sessionUnlocked && index == 6) {
        updateButton(kActiveMenu[index], "CERRAR VAULT", true,
                     index == focusIndex, Icon::lock);
      } else if (index == (sessionUnlocked ? 7 : 6)) {
        updateButton(kActiveMenu[index], "AJUSTES", true,
                     index == focusIndex, Icon::wrench);
      } else if (index == (sessionUnlocked ? 8 : 7)) {
        updateButton(kActiveMenu[index], "VOLVER AL MENU", true,
                     index == focusIndex, Icon::home);
      } else {
        const char* label = index == 4 && sessionUnlocked ? "ACCIONES EN VAULT" :
                            kActiveLabels[index];
        const Icon icon = index == 4 && sessionUnlocked ? Icon::folder :
                          kActiveIcons[index];
        updateButton(kActiveMenu[index], label, true, index == focusIndex, icon);
      }
      break;
    }
    case Screen::backup_seed:
      if (sessionUnlocked) {
        static const char* kVaultLabels[] = {"VER PALABRAS", "VER QR", "BACKUP SEEDQR", "VOLVER"};
        static const Icon kVaultIcons[] = {Icon::list, Icon::qr, Icon::qr, Icon::none};
        updateButton(kActiveMenu[index], kVaultLabels[index], true,
                     index == focusIndex, kVaultIcons[index]);
      } else {
        static const Icon kBackupIcons[] = {Icon::list, Icon::qr, Icon::qr,
                                            Icon::save, Icon::none};
        updateButton(kActiveMenu[index], kBackupLabels[index], true,
                     index == focusIndex, kBackupIcons[index]);
      }
      break;
    case Screen::vault_actions:
      if (index == 0) updateButton(kActiveMenu[0], "CARGAR SEMILLA", true, index == focusIndex, Icon::folder);
      else if (index == 1) updateButton(kActiveMenu[1], "GUARDAR SEMILLA ACTIVA", fingerprintValid, index == focusIndex, Icon::save);
      else if (index == 2) updateButton(kActiveMenu[2], "BLOQUEAR VAULT", true, index == focusIndex, Icon::lock);
      else updateButton(kActiveMenu[3], "VOLVER", true, index == focusIndex);
      break;
    case Screen::passphrase_input: {
      const size_t length = strlen(currentPassphraseEntry());
      updateButton(index == 0 ? kBack : kAction,
          index == 0 ? "CANCELAR" : passphraseConfirmPhase ? "ACTIVAR" : "CONTINUAR",
          index == 0 || length > 0, index == focusIndex,
          index == 0 ? Icon::none : Icon::key); break;
    }
    case Screen::length:
      if (index == 0) updateButton(kChoose12, "12 PALABRAS", true, index == focusIndex, Icon::list);
      else if (index == 1) updateButton(kChoose24, "24 PALABRAS", true, index == focusIndex, Icon::list);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::keyboard:
      updateButton(index == 0 ? kBack : kAction,
                   index == 0 ? "VOLVER" : "REVISAR", true, index == focusIndex,
                   index == 0 ? Icon::none : Icon::check); break;
    case Screen::review: {
      const bool valid = wordCount == targetWords && bip39::checksum_valid(words, targetWords);
      const char* actionLabel = newSeedIntent == NewSeedIntent::to_vault ? "GUARDAR EN VAULT" :
                                newSeedIntent == NewSeedIntent::ram_only ? "ACTIVAR EN RAM" :
                                "MENU SEED";
      const Icon actionIcon = newSeedIntent == NewSeedIntent::to_vault ? Icon::save :
                              newSeedIntent == NewSeedIntent::ram_only ? Icon::memory : Icon::none;
      if (index == 0) updateButton(kQrPrevious, "ULTIMA", true, index == focusIndex, Icon::draw);
      else if (index == 1) updateButton(kQrBack, actionLabel, valid, index == focusIndex, actionIcon);
      else updateButton(kQrNext, "VER QR", valid, index == focusIndex, Icon::qr);
      break;
    }
    case Screen::plain_qr:
      updateButton(kAction, "VOLVER AL MENU", true, true); break;
    case Screen::seedqr:
      if (index == 0) updateButton(kQrPrevious, "ANTERIOR", qrHasPrevious(), index == focusIndex, Icon::back);
      else if (index == 1) updateButton(kQrBack, "SALIR", true, index == focusIndex, Icon::x);
      else updateButton(kQrNext, "SIGUIENTE", qrHasNext(), index == focusIndex, Icon::forward);
      break;
    case Screen::public_key:
      if (index == 0) updateButton(kPublicQr, "MOSTRAR QR",
          publicExtendedKey.length(), index == focusIndex, Icon::qr);
      else if (index == 1) updateButton(kQrPrevious, "ANTERIOR", true, index == focusIndex, Icon::back);
      else if (index == 2) updateButton(kQrBack, "MENU SEED", true, index == focusIndex, Icon::home);
      else updateButton(kQrNext, "SIGUIENTE", true, index == focusIndex, Icon::forward);
      break;
    case Screen::public_key_qr:
      updateButton(kAction, "VOLVER A CLAVE", true, true); break;
    case Screen::entropy_length:
      if (index == 0) updateButton(kChoose12, "12 PALABRAS", true, index == focusIndex, Icon::list);
      else if (index == 1) updateButton(kChoose24, "24 PALABRAS", true, index == focusIndex, Icon::list);
      else if (index == 2) updateButton(kBack, "VOLVER", true, index == focusIndex);
      else updateButton(kAction, "TIRAR DADOS", true, index == focusIndex, Icon::dice);
      break;
    case Screen::dice:
      if (index == 0) updateButton(kDiceReset, "REINICIAR", true, index == focusIndex, Icon::reset);
      else if (index == 1) updateButton(kBack, "VOLVER", true, index == focusIndex);
      else updateButton(kAction, "CREAR SEMILLA", diceRolls >= diceTarget,
                        index == focusIndex, Icon::check);
      break;
    case Screen::entropy:
      if (index == 0) updateButton(kBack, "VOLVER", true, index == focusIndex);
      else updateButton(kEntropyCreate, "CREAR SEMILLA",
                        entropySamples >= kEntropyTarget && entropyHealthOk,
                        index == focusIndex, Icon::draw);
      break;
    case Screen::security_warning:
      updateButton(index == 0 ? kBack : kAction,
                   index == 0 ? "CANCELAR" : "ESTOY EN UN LUGAR SEGURO",
                   true, index == focusIndex,
                   index == 0 ? Icon::none : Icon::shield); break;
    case Screen::vault_password: {
      const size_t length = strlen(activeVaultPassword());
      const bool confirm = vaultConfirmPhase;
      updateButton(index == 0 ? kBack : kAction,
                   index == 0 ? "CANCELAR" : confirm ? "GUARDAR" : "CONTINUAR",
                   index == 0 || length >= 12, index == focusIndex,
                   index == 0 ? Icon::none : confirm ? Icon::lock : Icon::check); break;
    }
    case Screen::vault_result:
      updateButton(kAction, "VOLVER AL MENU SEED", true, true); break;
    case Screen::vault_label:
      updateButton(index == 0 ? kBack : kAction,
          index == 0 ? "CANCELAR" : "CONTINUAR",
          index == 0 || vaultLabel[0], index == focusIndex,
          index == 0 ? Icon::none : Icon::check); break;
    case Screen::vault_list:
      if (index < vaultFileCount)
        updateButton(kVaultFiles[index], vaultDisplayName(index), true, index == focusIndex);
      else if (index == vaultFileCount) updateButton(kBack, "VOLVER", true, index == focusIndex);
      else updateButton(kAction, vaultDeleteMode ? "CANCELAR ELIMINACION" : "MODO ELIMINAR",
                        vaultFileCount > 0, index == focusIndex, Icon::trash);
      break;
    case Screen::vault_unlock:
      updateButton(index == 0 ? kBack : kAction,
          index == 0 ? "VOLVER" : "DESBLOQUEAR",
          index == 0 || strlen(vaultPassword) >= 1, index == focusIndex,
          index == 0 ? Icon::none : Icon::unlock); break;
    case Screen::vault_loaded:
      updateButton(kAction, "ABRIR SEMILLA", true, true, Icon::folder); break;
    case Screen::session_menu: {
      const char* labelsLocked[] = {"CREAR VAULT", "DESBLOQUEAR VAULT", "VOLVER"};
      const char* labelsOpen[] = {"CARGAR SEMILLA", "BLOQUEAR VAULT", "VOLVER"};
      const Icon iconsLocked[] = {Icon::plus, Icon::unlock, Icon::none};
      const Icon iconsOpen[] = {Icon::folder, Icon::lock, Icon::none};
      updateButton(kMenu[index], sessionUnlocked ? labelsOpen[index] : labelsLocked[index],
          true, index == focusIndex,
          sessionUnlocked ? iconsOpen[index] : iconsLocked[index]); break;
    }
    case Screen::session_meta_list:
      if (index < sessionMetaCount) updateButton(kVaultFiles[index], sessionMetaFiles[index] + 1, true, index == focusIndex);
      else updateButton(kBack, "VOLVER", true, index == focusIndex); break;
    case Screen::session_seed_list:
      if (index < sessionSeedCount) {
        updateButton(kVaultFiles[index], sessionSeedFiles[index] + 1, true, index == focusIndex);
      } else if (sessionDeleteMode) {
        if (index == sessionSeedCount) updateButton(kSessionBack, "VOLVER", true, index == focusIndex);
        else updateButton(kSessionAction, "CANCELAR ELIMINACION", sessionSeedCount > 0, index == focusIndex, Icon::trash);
      } else if (index == sessionSeedCount) {
        updateButton(kSessionNewVault, "CARGAR NUEVA SEED", true, index == focusIndex, Icon::plus);
      } else if (index == sessionSeedCount + 1) {
        updateButton(kSessionNewEntropy, "GENERAR ENTROPIA", true, index == focusIndex, Icon::draw);
      } else if (index == sessionSeedCount + 2) {
        updateButton(kSessionNewRam, "CARGAR SOLO EN RAM", true, index == focusIndex, Icon::memory);
      } else if (index == sessionSeedCount + 3) {
        updateButton(kSessionBack, "VOLVER", true, index == focusIndex);
      } else {
        updateButton(kSessionAction, "MODO ELIMINAR", sessionSeedCount > 0, index == focusIndex, Icon::trash);
      }
      break;
    case Screen::delete_confirm:
      updateButton(index == 0 ? kBack : kAction,
          index == 0 ? "CANCELAR" : "ELIMINAR ARCHIVO", true, index == focusIndex,
          index == 0 ? Icon::none : Icon::trash); break;
    case Screen::address_explorer: {
      const PublicProfile& profile = kPublicProfiles[publicKeyProfile];
      String profileLabel = String("TIPO: ") + profile.title;
      if (index == 0) updateButton(kAddressReceive, "RECIBIR", true, index == focusIndex, Icon::down);
      else if (index == 1) updateButton(kAddressChange, "CAMBIO", true, index == focusIndex, Icon::up);
      else if (index == 2) updateButton(kAddressMinus, "- 1", addressIndex > 0, index == focusIndex, Icon::minus);
      else if (index == 3) updateButton(kAddressPlus, "+ 1", addressIndex < 999999, index == focusIndex, Icon::plus);
      else if (index == 4) updateButton(kAddressProfile, profileLabel.c_str(), true, index == focusIndex);
      else if (index == 5) updateButton(kBack, "MENU SEED", true, index == focusIndex, Icon::home);
      else updateButton(kAction, "QR DIRECCION", activeAddress.length(), index == focusIndex, Icon::qr);
      break;
    }
    case Screen::address_index_input:
      updateButton(index == 0 ? kBack : kAction,
          index == 0 ? "CANCELAR" : "IR A INDICE",
          index == 0 || indexBuffer[0], index == focusIndex,
          index == 0 ? Icon::none : Icon::check); break;
    case Screen::address_qr:
      updateButton(kAction, "VOLVER AL EXPLORADOR", true, true); break;
    case Screen::discard_confirm:
      updateButton(index == 0 ? kBack : kAction,
                   index == 0 ? "CANCELAR" : "CONFIRMAR DESCARTE",
                   true, index == focusIndex,
                   index == 0 ? Icon::none : Icon::trash); break;
    case Screen::unlock_confirm:
      updateButton(index == 0 ? kBack : kAction,
                   index == 0 ? "CANCELAR" : "CONTINUAR",
                   true, index == focusIndex,
                   index == 0 ? Icon::none : Icon::folder); break;
    case Screen::diagnostics: break;
    case Screen::scan_qr: {
      const auto p = qrClient.phase();
      if (p == qr_ble::Phase::Failed) {
        if (index == 0) updateButton(kBack, "VOLVER", true, index == focusIndex);
        else updateButton(kAction, "REINTENTAR", true, index == focusIndex, Icon::reset);
      } else if (p == qr_ble::Phase::Success) {
        updateButton(kAction, "VOLVER", true, index == focusIndex);
      } else {
        updateButton(kAction, "CANCELAR", true, index == focusIndex, Icon::x);
      }
      break;
    }
    case Screen::wifi_receive: {
      const auto p = wifiServer.phase();
      if (p == qr_wifi::Phase::Failed) {
        if (index == 0) updateButton(kBack, "VOLVER", true, index == focusIndex);
        else updateButton(kAction, "REINTENTAR", true, index == focusIndex, Icon::reset);
      } else if (p == qr_wifi::Phase::Received) {
        if (wifiServer.mode() == qr_wifi::Mode::kSeedText) {
          if (index == 0) updateButton(kBack, "VOLVER", true, index == focusIndex);
          else updateButton(kAction, "REINTENTAR", true, index == focusIndex, Icon::reset);
        } else if (txIsPsbt) {
          if (index == 0) updateButton(kBack, "VOLVER", true, index == focusIndex);
          else if (index == 1) updateButton(kDetail, "DETALLE", true, index == focusIndex, Icon::list);
          else updateButton(kFirmar, "FIRMAR", true, index == focusIndex, Icon::key);
        } else {
          updateButton(kAction, "VOLVER", true, index == focusIndex);
        }
      } else {
        updateButton(kAction, "CANCELAR", true, index == focusIndex, Icon::x);
      }
      break;
    }
    case Screen::wifi_mode: {
      static const Icon kWifiModeIcons[] = {Icon::wifi, Icon::wifi, Icon::key, Icon::none};
      static const char* kWifiModeLabels[] = {"SUBIR FICHERO (PSBT)",
                                              "PEGAR TRANSACCION (PSBT)",
                                              "PEGAR SEMILLA BIP39", "VOLVER"};
      const bool psbtOk = fingerprintValid;
      if (index == 0 || index == 1) updateButton(kMenu[index], kWifiModeLabels[index], psbtOk,
                                                 index == focusIndex, kWifiModeIcons[index]);
      else if (index == 2) updateButton(kMenu[index], kWifiModeLabels[index], true,
                                        index == focusIndex, kWifiModeIcons[index]);
      else updateButton(kBack, kWifiModeLabels[3], true, index == focusIndex);
      break;
    }
    case Screen::settings: {
      if (index == 0) updateButton(kMenu[0], settingsLangLabel().c_str(), true, index == focusIndex);
      else if (index == 1) updateButton(kMenu[1], settingsTimeoutLabel().c_str(), true, index == focusIndex, Icon::lock);
      else if (index == 2) updateButton(kMenu[2], settingsCleanLabel().c_str(), true, index == focusIndex, Icon::trash);
      else if (index == 3) updateButton(kMenu[3], settingsDerivLabel().c_str(), true, index == focusIndex, Icon::key);
      else if (index == 4) updateButton(kMenu[4], "Estado de la radio", true, index == focusIndex, Icon::wifi);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    }
    case Screen::settings_lang:
      if (index == 0) updateButton(kMenu[0], "Ingles", true, index == focusIndex && gSettings.language == 0);
      else if (index == 1) updateButton(kMenu[1], "Espanol", true, index == focusIndex && gSettings.language == 1);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::settings_timeout:
      if (index < device_settings::kTimeoutOptionCount)
        updateButton(kMenu[index], timeoutLabel(device_settings::kTimeoutOptions[index]), true,
                     index == focusIndex && gSettings.lockTimeoutMs == device_settings::kTimeoutOptions[index], Icon::lock);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::settings_clean:
      if (index < device_settings::kCleanOptionCount)
        updateButton(kMenu[index], cleanLabel(device_settings::kCleanOptions[index]), true,
                     index == focusIndex && gSettings.seedCleanTimeoutMs == device_settings::kCleanOptions[index], Icon::trash);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::settings_derivation:
      if (index < kPublicProfileCount)
        updateButton(kMenu[index], profileLabel(index), true,
                     index == focusIndex && gSettings.defaultProfile == index, Icon::key);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::settings_radio:
      updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::multisig_confirm:
      if (index == 0) updateButton(kBack, "CANCELAR", true, index == focusIndex);
      else updateButton(kFirmar, "FIRMAR", true, index == focusIndex, Icon::key);
      break;
    case Screen::tx_history:
      if (index < txFileCount) updateButton(kVaultFiles[index], txDisplayName(index), true, index == focusIndex);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::tx_review:
      if (index == 0) updateButton(kBack, "VOLVER", true, index == focusIndex);
      else if (index == 1) updateButton(kDetail, "DETALLE", true, index == focusIndex, Icon::list);
      else updateButton(kFirmar, "FIRMAR", true, index == focusIndex, Icon::key);
      break;
    case Screen::utxo_detail:
      updateButton(kAction, "VOLVER", true, index == focusIndex);
      break;
    case Screen::signed_tx:
      updateButton(kAction, "VOLVER", true, index == focusIndex);
      break;
    case Screen::signed_mode:
      if (index == 0) updateButton(kMenu[0], "SPARROW (QR estatico)", true, index == focusIndex, Icon::qr);
      else if (index == 1) updateButton(kMenu[1], "BLUEWALLET (QR animado)", !txIsMultisig, index == focusIndex, Icon::qr);
      else updateButton(kBack, "VOLVER", true, index == focusIndex);
      break;
    case Screen::animated_qr:
      updateButton(kAction, "VOLVER", true, index == focusIndex);
      break;
  }
}

void moveFocus(int direction) {
  const uint8_t previous = focusIndex;
  uint8_t count = 1;
  if (screen == Screen::active_seed) count = sessionUnlocked ? 9 : 8;
  else if (screen == Screen::seed_switcher) count = loadedSeedCount + 1;
  else if (screen == Screen::backup_seed) count = sessionUnlocked ? 4 : 5;
  else if (screen == Screen::vault_actions) count = 4;
  else if (screen == Screen::public_key) count = 4;
  else if (screen == Screen::menu) count = 7;
  else if (screen == Screen::scan_qr)
    count = qrClient.phase() == qr_ble::Phase::Failed ? 2 : 1;
  else if (screen == Screen::wifi_receive) {
    if (wifiServer.phase() == qr_wifi::Phase::Failed) count = 2;
    else if (wifiServer.phase() == qr_wifi::Phase::Received &&
             wifiServer.mode() == qr_wifi::Mode::kSeedText) count = 2;
    else if (wifiServer.phase() == qr_wifi::Phase::Received && txIsPsbt)
      count = fingerprintValid ? 3 : 2;
    else count = 1;
  }
  else if (screen == Screen::wifi_mode) count = 4;
  else if (screen == Screen::settings) count = 6;
  else if (screen == Screen::settings_lang) count = 3;
  else if (screen == Screen::settings_timeout) count = device_settings::kTimeoutOptionCount + 1;
  else if (screen == Screen::settings_clean) count = device_settings::kCleanOptionCount + 1;
  else if (screen == Screen::settings_derivation) count = kPublicProfileCount + 1;
  else if (screen == Screen::settings_radio) count = 1;
  else if (screen == Screen::multisig_confirm) count = 2;
  else if (screen == Screen::tx_history) count = txFileCount + 1;
  else if (screen == Screen::signed_tx) count = 1;
  else if (screen == Screen::signed_mode) count = 3;
  else if (screen == Screen::animated_qr) count = 1;
  else if (screen == Screen::tx_review) count = fingerprintValid ? 3 : 2;
  else if (screen == Screen::utxo_detail) count = 1;
  else if (screen == Screen::vault_list) count = vaultFileCount + 2;
  else if (screen == Screen::session_menu) count = 3;
  else if (screen == Screen::session_meta_list) count = sessionMetaCount + 1;
  else if (screen == Screen::session_seed_list) count = sessionDeleteMode ? sessionSeedCount + 2 : sessionSeedCount + 5;
  else if (screen == Screen::length || screen == Screen::seedqr) count = 3;
  else if (screen == Screen::entropy_length) count = 4;
  else if (screen == Screen::dice) count = 3;
  else if (screen == Screen::review) count = 3;
  else if (screen == Screen::keyboard || screen == Screen::entropy ||
           screen == Screen::security_warning || screen == Screen::vault_password ||
           screen == Screen::vault_label || screen == Screen::vault_unlock ||
           screen == Screen::passphrase_input ||
           screen == Screen::address_index_input ||
           screen == Screen::delete_confirm || screen == Screen::discard_confirm ||
           screen == Screen::unlock_confirm) count = 2;
  else if (screen == Screen::address_explorer) count = 7;
  focusIndex = static_cast<uint8_t>((focusIndex + direction + count) % count);
  if (screen == Screen::menu) {
    const bool skip = (fingerprintValid && focusIndex == 1);
    if (skip) focusIndex = static_cast<uint8_t>((focusIndex + direction + count) % count);
  }
  updateFocusButton(previous);
  if (previous != focusIndex) updateFocusButton(focusIndex);
}

void discardActiveSeed() {
  if (entropySourceActive) { bootloader_random_disable(); entropySourceActive = false; }
  clearPassphrase(); memset(words, 0, sizeof(words));
  memset(entropyState, 0, sizeof(entropyState));
  memset(seedqrBuffer, 0, sizeof(seedqrBuffer));
  memset(publicKeyQrBuffer, 0, sizeof(publicKeyQrBuffer));
  publicExtendedKey = "";
  activeAddress = "";
  memset(addressQrBuffer, 0, sizeof(addressQrBuffer));
  encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
  encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
  memset(vaultLabel, 0, sizeof(vaultLabel));
  encrypted_seed_store::wipe(loadedSeeds, sizeof(loadedSeeds));
  loadedSeedCount = 0; activeLoadedSeed = -1;
  prefix = ""; wordCount = 0; editingWord = -1;
  clearFingerprint();
}

bool discardCurrentSeed() {
  if (activeLoadedSeed < 0 || loadedSeedCount <= 1) {
    discardActiveSeed(); return false;
  }
  const uint8_t removed = static_cast<uint8_t>(activeLoadedSeed);
  encrypted_seed_store::wipe(words, sizeof(words)); clearDerivedData();
  prefix = ""; wordCount = 0; editingWord = -1; clearFingerprint();
  for (uint8_t i = removed; i + 1 < loadedSeedCount; ++i) loadedSeeds[i] = loadedSeeds[i + 1];
  encrypted_seed_store::wipe(&loadedSeeds[loadedSeedCount - 1], sizeof(LoadedSeed));
  --loadedSeedCount; activeLoadedSeed = -1;
  return activateLoadedSeed(removed < loadedSeedCount ? removed : loadedSeedCount - 1);
}

void click(int x, int y) {
  if (fingerprintValid && screen != Screen::vault_password &&
      screen != Screen::vault_label && screen != Screen::vault_unlock &&
      screen != Screen::passphrase_input &&
      screen != Screen::scan_qr &&
      kFingerprintBadge.contains(x, y)) {
    if (sessionUnlocked) {
      cacheCurrentSeed();
      screen = Screen::seed_switcher;
      focusIndex = activeLoadedSeed >= 0 ? static_cast<uint8_t>(activeLoadedSeed) : 0;
      drawScreen();
    }
    else openPublicKey(gSettings.defaultProfile);
    return;
  }
  if (screen == Screen::menu) {
    if (kMenu[0].contains(x, y)) {
      if (fingerprintValid) { screen = Screen::active_seed; focusIndex = 0; drawScreen(); }
      else { newSeedIntent = NewSeedIntent::none; screen = Screen::length; focusIndex = 0; drawScreen(); }
    } else if (kMenu[1].contains(x, y)) {
      if (!fingerprintValid) { newSeedIntent = NewSeedIntent::none; screen = Screen::entropy_length; focusIndex = 0; drawScreen(); }
    }     else if (kMenu[2].contains(x, y)) { screen = Screen::session_menu; focusIndex = 0; drawScreen(); }
    else if (kMenu[3].contains(x, y)) { openWifiMode(); }
    else if (kMenu[4].contains(x, y)) { openTxHistory(); }
    else if (kMenu[5].contains(x, y)) { screen = Screen::settings; focusIndex = 0; drawScreen(); }
    else if (kMenu[6].contains(x, y)) { lockDevice(); }
    else if (kHelpIcon.contains(x, y)) { screen = Screen::help; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::active_seed) {
    if (kActiveMenu[0].contains(x, y)) { openPublicKey(gSettings.defaultProfile); }
    else if (kActiveMenu[1].contains(x, y)) {
      screen = Screen::backup_seed; focusIndex = 0; drawScreen();
    }
    else if (kActiveMenu[2].contains(x, y)) { beginPassphrase(); }
    else if (kActiveMenu[3].contains(x, y)) { openAddressExplorer(); }
    else if (kActiveMenu[4].contains(x, y)) {
      if (sessionUnlocked) { screen = Screen::vault_actions; focusIndex = 0; drawScreen(); }
      else { screen = Screen::discard_confirm; focusIndex = 0; drawScreen(); }
    }
    else if (kActiveMenu[5].contains(x, y)) { openWifiMode(); }
    else if (sessionUnlocked && kActiveMenu[6].contains(x, y)) lockSessionVault();
    else if (kActiveMenu[sessionUnlocked ? 7 : 6].contains(x, y)) {
      screen = Screen::settings; focusIndex = 0; drawScreen();
    }
    else if (kActiveMenu[sessionUnlocked ? 8 : 7].contains(x, y)) {
      screen = Screen::menu; focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::seed_switcher) {
    for (uint8_t i = 0; i < loadedSeedCount; ++i) if (kVaultFiles[i].contains(x, y)) {
      if (activateLoadedSeed(i)) { screen = Screen::active_seed; focusIndex = 0; drawScreen(); }
      return;
    }
    if (kBack.contains(x, y)) { screen = Screen::active_seed; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::passphrase_input) {
    char* value = currentPassphraseEntry(); size_t length = strlen(value);
    const char key = passphraseKeyAt(x, y);
    if (key && length < sizeof(passphraseEntry) - 1) {
      value[length] = key; value[length + 1] = '\0'; drawPassphraseInput();
    } else if (kPassSpace.contains(x, y) && length < sizeof(passphraseEntry) - 1) {
      value[length] = ' '; value[length + 1] = '\0'; drawPassphraseInput();
    } else if (kDelete.contains(x, y) && length) {
      value[length - 1] = '\0'; drawPassphraseInput();
    } else if (kPassMode.contains(x, y)) {
      passphraseKeyboardMode = (passphraseKeyboardMode + 1) % 4; drawPassphraseInput();
    } else if (kPassReveal.contains(x, y) && length) {
      passphraseReveal = !passphraseReveal; drawPassphraseInput();
    } else if (kPassRemove.contains(x, y) && passphraseActive) {
      clearPassphrase(); clearDerivedData(); updateFingerprint();
      screen = Screen::active_seed; focusIndex = 2; drawScreen();
      showToast("PASSPHRASE QUITADA");
    } else if ((kAdd.contains(x, y) || kAction.contains(x, y)) && length) {
      if (!passphraseConfirmPhase) {
        passphraseConfirmPhase = true; passphraseReveal = false;
        focusIndex = 0; drawPassphraseInput();
      } else if (strcmp(passphraseEntry, passphraseConfirmation) != 0) {
        encrypted_seed_store::wipe(passphraseConfirmation, sizeof(passphraseConfirmation));
        passphraseMismatch = true; passphraseReveal = false; drawPassphraseInput();
      } else {
        encrypted_seed_store::wipe(activePassphrase, sizeof(activePassphrase));
        strncpy(activePassphrase, passphraseEntry, sizeof(activePassphrase) - 1);
        encrypted_seed_store::wipe(passphraseEntry, sizeof(passphraseEntry));
        encrypted_seed_store::wipe(passphraseConfirmation, sizeof(passphraseConfirmation));
        passphraseActive = true; passphraseConfirmPhase = false;
        passphraseMismatch = false; passphraseReveal = false;
        clearDerivedData(); updateFingerprint();
        screen = Screen::active_seed; focusIndex = 2; drawScreen();
        showToast("PASSPHRASE ACTIVA");
      }
    } else if (kBack.contains(x, y)) {
      encrypted_seed_store::wipe(passphraseEntry, sizeof(passphraseEntry));
      encrypted_seed_store::wipe(passphraseConfirmation, sizeof(passphraseConfirmation));
      passphraseConfirmPhase = false; passphraseMismatch = false; passphraseReveal = false;
      screen = Screen::active_seed; focusIndex = 2; drawScreen();
    }
  } else if (screen == Screen::backup_seed) {
    if (kActiveMenu[0].contains(x, y)) {
      requestSecurity(Screen::review, Screen::active_seed);
    }
    else if (kActiveMenu[1].contains(x, y) && buildSeedQR()) {
      requestSecurity(Screen::plain_qr, Screen::active_seed);
    }
    else if (kActiveMenu[2].contains(x, y) && buildSeedQR()) {
      seedqrRow = 0; seedqrRun = 0;
      requestSecurity(Screen::seedqr, Screen::active_seed);
    }
    else if (sessionUnlocked && kActiveMenu[3].contains(x, y)) {
      screen = Screen::active_seed; focusIndex = 1; drawScreen();
    }
    else if (!sessionUnlocked && kActiveMenu[3].contains(x, y)) {
      screen = Screen::session_menu; focusIndex = 0; drawScreen();
    }
    else if (kActiveMenu[4].contains(x, y)) { screen = Screen::active_seed; focusIndex = 1; drawScreen(); }
  } else if (screen == Screen::vault_actions) {
    if (kActiveMenu[0].contains(x, y)) { sessionDeleteMode = false; screen = Screen::session_seed_list; focusIndex = 0; drawScreen(); }
    else if (kActiveMenu[1].contains(x, y) && fingerprintValid) beginSessionSave();
    else if (kActiveMenu[2].contains(x, y)) lockSessionVault();
    else if (kActiveMenu[3].contains(x, y)) { screen = Screen::active_seed; focusIndex = 4; drawScreen(); }
  } else if (screen == Screen::length) {
    if (kChoose12.contains(x, y) || kChoose24.contains(x, y)) {
      resetPhrase(kChoose12.contains(x, y) ? 12 : 24);
      screen = Screen::keyboard; focusIndex = 0; drawScreen();
    } else if (kBack.contains(x, y)) {
      if (newSeedIntent != NewSeedIntent::none) {
        newSeedIntent = NewSeedIntent::none;
        screen = Screen::session_seed_list; focusIndex = 0; drawScreen();
      } else { screen = Screen::menu; focusIndex = 0; drawScreen(); }
    }
  } else if (screen == Screen::keyboard) {
    uint16_t matches[4] = {};
    const size_t count = currentSuggestions(matches);
    for (uint8_t i = 0; i < min(count, static_cast<size_t>(4)); ++i)
      if (kSuggestion[i].contains(x, y)) { commitWord(matches[i]); return; }
    const char key = keyAt(x, y);
    if (key && prefix.length() < 12) {
      String candidate = prefix + key;
      if (bip39::has_prefix(candidate)) { prefix = candidate; updateKeyboardDynamic(); }
    } else if (kDelete.contains(x, y) && prefix.length()) {
      prefix.remove(prefix.length() - 1); updateKeyboardDynamic();
    } else if (kAdd.contains(x, y)) {
      uint16_t selected = bip39::find_exact(prefix);
      if (selected == bip39::kInvalidWord && count == 1) selected = matches[0];
      commitWord(selected);
    } else if (kBack.contains(x, y)) {
      if (editingWord >= 0) { editingWord = -1; prefix = ""; screen = Screen::review; }
      else if (newSeedIntent != NewSeedIntent::none) {
        newSeedIntent = NewSeedIntent::none; screen = Screen::session_seed_list;
      }
      else screen = Screen::menu;
      focusIndex = 0; drawScreen();
    }
    else if (kAction.contains(x, y)) {
      requestSecurity(Screen::review, Screen::keyboard);
    }
  } else if (screen == Screen::review) {
    const int selectedWord = reviewWordAt(x, y);
    if (selectedWord >= 0) { editWord(static_cast<uint8_t>(selectedWord)); }
    else if (kQrPrevious.contains(x, y)) {
      if (wordCount) editWord(wordCount - 1);
      else { screen = Screen::keyboard; focusIndex = 0; drawScreen(); }
    }
    else if (kQrBack.contains(x, y) && fingerprintValid) {
      if (newSeedIntent == NewSeedIntent::to_vault) {
        newSeedIntent = NewSeedIntent::none;
        beginSessionSave();
      } else {
        newSeedIntent = NewSeedIntent::none;
        screen = Screen::active_seed; focusIndex = 0; drawScreen();
      }
    }
    else if (kQrNext.contains(x, y) && buildSeedQR()) { newSeedIntent = NewSeedIntent::none; screen = Screen::plain_qr; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::plain_qr) {
    if (kAction.contains(x, y)) { screen = Screen::active_seed; focusIndex = 1; drawScreen(); }
  } else if (screen == Screen::seedqr) {
    if (kQrPrevious.contains(x, y) && qrHasPrevious()) { qrPreviousStep(); renderQrDynamic(); }
    else if (kQrNext.contains(x, y) && qrHasNext()) { qrNextStep(); renderQrDynamic(); }
    else if (kQrBack.contains(x, y)) { screen = Screen::active_seed; focusIndex = 2; drawScreen(); }
  } else if (screen == Screen::public_key) {
    if (kPublicQr.contains(x, y) && buildPublicKeyQr()) {
      screen = Screen::public_key_qr; focusIndex = 0; drawScreen();
    } else if (kQrPrevious.contains(x, y) && hdSelfTest) {
      openPublicKey((publicKeyProfile + kPublicProfileCount - 1) % kPublicProfileCount);
    }
    else if (kQrBack.contains(x, y)) {
      screen = Screen::active_seed; focusIndex = 0; drawScreen();
    } else if (kQrNext.contains(x, y) && hdSelfTest) {
      openPublicKey((publicKeyProfile + 1) % kPublicProfileCount);
    }
  } else if (screen == Screen::public_key_qr) {
    if (kAction.contains(x, y)) { screen = Screen::public_key; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::entropy_length) {
    if (kChoose12.contains(x, y) || kChoose24.contains(x, y)) {
      resetPhrase(kChoose12.contains(x, y) ? 12 : 24);
      initEntropy();
      screen = Screen::entropy; focusIndex = 0; drawScreen();
    } else if (kBack.contains(x, y)) {
      if (newSeedIntent != NewSeedIntent::none) {
        newSeedIntent = NewSeedIntent::none;
        screen = Screen::session_seed_list; focusIndex = 0; drawScreen();
      } else { screen = Screen::menu; focusIndex = 0; drawScreen(); }
    } else if (kAction.contains(x, y)) {
      // Respeta la longitud elegida en la pantalla de dados (12/24) en lugar de
      // forzar 12 palabras.
      initDice();
      screen = Screen::dice; focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::dice) {
    if (kDiceLength12.contains(x, y) && diceTargetWords != 12) {
      diceTargetWords = 12; initDice(); drawScreen();
    } else if (kDiceLength24.contains(x, y) && diceTargetWords != 24) {
      diceTargetWords = 24; initDice(); drawScreen();
    } else if (kDiceReset.contains(x, y)) {
      initDice(); drawScreen();
    } else if (kBack.contains(x, y)) {
      encrypted_seed_store::wipe(diceState, sizeof(diceState)); diceRolls = 0;
      screen = Screen::entropy_length; focusIndex = 0; drawScreen();
    } else if (kAction.contains(x, y) && diceRolls >= diceTarget) {
      finishDice();
    } else {
      for (uint8_t i = 0; i < 6; ++i) {
        if (kDiceValue[i].contains(x, y)) { registerDiceRoll(i + 1); return; }
      }
    }
  } else if (screen == Screen::entropy) {
    if (kEntropyReset.contains(x, y)) { initEntropy(); drawScreen(); }
    else if (kEntropyCreate.contains(x, y)) finishEntropy();
    else if (kBack.contains(x, y)) {
      if (entropySourceActive) { bootloader_random_disable(); entropySourceActive = false; }
      encrypted_seed_store::wipe(entropyState, sizeof(entropyState));
      if (newSeedIntent != NewSeedIntent::none) {
        newSeedIntent = NewSeedIntent::none;
        screen = Screen::session_seed_list; focusIndex = 0; drawScreen();
      } else { screen = Screen::menu; focusIndex = 0; drawScreen(); }
    }
  } else if (screen == Screen::security_warning) {
    if (kBack.contains(x, y)) {
      screen = securityWarningReturn; focusIndex = 0; drawScreen();
    } else if (kAction.contains(x, y)) {
      screen = securityWarningTarget; focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::vault_label) {
    const size_t length = strlen(vaultLabel);
    const char key = keyAt(x, y);
    if (key && length < 16) {
      vaultLabel[length] = key; vaultLabel[length + 1] = '\0';
      updateVaultLabelDynamic(length == 0);
    } else if (kDelete.contains(x, y) && length) {
      vaultLabel[length - 1] = '\0'; updateVaultLabelDynamic(length == 1);
    } else if ((kAdd.contains(x, y) || kAction.contains(x, y)) && vaultLabel[0]) {
      if (vaultFlow == VaultFlow::session_save_seed) saveSeedToSession();
      else { screen = Screen::vault_password; focusIndex = 0; drawVaultPassword(); }
    } else if (kBack.contains(x, y)) {
      memset(vaultLabel, 0, sizeof(vaultLabel));
      if (vaultFlow == VaultFlow::individual) { screen = Screen::backup_seed; focusIndex = 3; }
      else { screen = Screen::session_menu; focusIndex = 0; }
      drawScreen();
    }
  } else if (screen == Screen::vault_list) {
    for (uint8_t i = 0; i < vaultFileCount; ++i) {
      if (kVaultFiles[i].contains(x, y)) {
        if (vaultDeleteMode) {
          strncpy(pendingDeletePath, vaultFiles[i], sizeof(pendingDeletePath) - 1);
          pendingDeleteSession = false; deleteFailed = false;
          screen = Screen::delete_confirm; focusIndex = 0; drawScreen(); return;
        }
        selectedVaultFile = i; memset(vaultPassword, 0, sizeof(vaultPassword));
        vaultUnlockError = false; vaultRevealUntil = 0;
        screen = Screen::vault_unlock; focusIndex = 0; drawVaultUnlock(); return;
      }
    }
    if (kBack.contains(x, y)) { screen = Screen::menu; focusIndex = 2; drawScreen(); }
    else if (kAction.contains(x, y) && vaultFileCount) {
      vaultDeleteMode = !vaultDeleteMode; focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::vault_unlock) {
    const size_t length = strlen(vaultPassword); const char key = keyAt(x, y);
    if (key && length < 24) {
      vaultPassword[length] = key; vaultPassword[length + 1] = '\0';
      vaultUnlockError = false; updateVaultPasswordDynamic(length == 0);
    } else if (kDelete.contains(x, y) && length) {
      vaultPassword[length - 1] = '\0'; updateVaultPasswordDynamic(length == 1);
    } else if ((kAdd.contains(x, y) || kAction.contains(x, y)) && length) {
      if (fingerprintValid) {
        unlockConfirmIsSession = (vaultFlow == VaultFlow::session_unlock);
        screen = Screen::unlock_confirm; focusIndex = 0; drawScreen();
      } else if (vaultFlow == VaultFlow::session_unlock) unlockSessionVault();
      else loadSelectedVault();
    } else if (kVaultReveal.contains(x, y) && length) {
      vaultRevealUntil = millis() + 3000; updateVaultPasswordDynamic();
      updateButton(kVaultReveal, "VISIBLE 3 SEG.", true, true, Icon::eye, UPDATE_MODE_A2);
    } else if (kBack.contains(x, y)) {
      encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
      if (vaultFlow == VaultFlow::session_unlock) {
        screen = Screen::session_meta_list; focusIndex = selectedSessionFile;
      } else { screen = Screen::vault_list; focusIndex = selectedVaultFile; }
      drawScreen();
    }
  } else if (screen == Screen::vault_password) {
    char* value = activeVaultPassword();
    size_t length = strlen(value);
    const char key = keyAt(x, y);
    if (key && length < 24) {
      value[length] = key; value[length + 1] = '\0';
      updateVaultPasswordDynamic(length == 11);
    } else if (kDelete.contains(x, y) && length) {
      value[length - 1] = '\0'; updateVaultPasswordDynamic(length == 12);
    } else if ((kAdd.contains(x, y) || kAction.contains(x, y)) && length >= 12) {
      if (!vaultConfirmPhase) {
        vaultConfirmPhase = true; vaultRevealUntil = 0;
        focusIndex = 0; drawVaultPassword();
      } else if (vaultFlow == VaultFlow::session_create) createSessionVault();
      else saveVault();
    } else if (kVaultReveal.contains(x, y) && length) {
      vaultRevealUntil = millis() + 3000;
      updateVaultPasswordDynamic();
      updateButton(kVaultReveal, "VISIBLE 3 SEG.", true, true, Icon::eye, UPDATE_MODE_A2);
    } else if (kBack.contains(x, y)) {
      encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
      encrypted_seed_store::wipe(vaultConfirmation, sizeof(vaultConfirmation));
      vaultConfirmPhase = false; vaultRevealUntil = 0;
      screen = Screen::vault_label; focusIndex = 1; drawScreen();
    }
  } else if (screen == Screen::vault_result) {
    if (kAction.contains(x, y)) {
      if (vaultFlow == VaultFlow::session_save_seed || vaultFlow == VaultFlow::session_create) {
        screen = Screen::session_menu; focusIndex = 0;
      } else { screen = Screen::backup_seed; focusIndex = 3; }
      drawScreen();
    }
  } else if (screen == Screen::vault_loaded) {
    if (kAction.contains(x, y)) {
      screen = Screen::active_seed; focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::session_menu) {
    if (!sessionUnlocked) {
      if (kMenu[0].contains(x, y)) beginSessionCreate();
      else if (kMenu[1].contains(x, y)) { scanSessionMeta(); screen = Screen::session_meta_list; focusIndex = 0; drawScreen(); }
      else if (kMenu[2].contains(x, y)) { screen = Screen::menu; focusIndex = 2; drawScreen(); }
    } else {
      if (kMenu[0].contains(x, y)) { sessionDeleteMode = false; scanSessionSeeds(); screen = Screen::session_seed_list; focusIndex = 0; drawScreen(); }
      else if (kMenu[1].contains(x, y)) lockSessionVault();
      else if (kMenu[2].contains(x, y)) { screen = Screen::menu; focusIndex = 2; drawScreen(); }
    }
  } else if (screen == Screen::session_meta_list) {
    for (uint8_t i = 0; i < sessionMetaCount; ++i) if (kVaultFiles[i].contains(x, y)) {
      selectedSessionFile = i; vaultFlow = VaultFlow::session_unlock;
      encrypted_seed_store::wipe(vaultPassword, sizeof(vaultPassword));
      vaultUnlockError = false; vaultRevealUntil = 0;
      screen = Screen::vault_unlock; focusIndex = 0; drawScreen(); return;
    }
    if (kBack.contains(x, y)) { sessionDeleteMode = false; screen = Screen::session_menu; focusIndex = 1; drawScreen(); }
  } else if (screen == Screen::session_seed_list) {
    for (uint8_t i = 0; i < sessionSeedCount; ++i) if (kVaultFiles[i].contains(x, y)) {
      if (sessionDeleteMode) {
        strncpy(pendingDeletePath, sessionSeedFiles[i], sizeof(pendingDeletePath) - 1);
        pendingDeleteSession = true; deleteFailed = false;
        screen = Screen::delete_confirm; focusIndex = 0; drawScreen(); return;
      }
      loadSeedFromSession(i); return;
    }
    if (!sessionDeleteMode) {
      if (kSessionNewVault.contains(x, y)) { beginNewSeedFromSession(NewSeedIntent::to_vault); return; }
      if (kSessionNewEntropy.contains(x, y)) { beginEntropyFromSession(); return; }
      if (kSessionNewRam.contains(x, y)) { beginNewSeedFromSession(NewSeedIntent::ram_only); return; }
    }
    if (kSessionBack.contains(x, y)) { sessionDeleteMode = false; screen = Screen::session_menu; focusIndex = 1; drawScreen(); }
    else if (kSessionAction.contains(x, y) && sessionSeedCount) {
      sessionDeleteMode = !sessionDeleteMode; focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::delete_confirm) {
    if (kBack.contains(x, y)) {
      screen = pendingDeleteSession ? Screen::session_seed_list : Screen::vault_list;
      focusIndex = 0; drawScreen();
    } else if (kAction.contains(x, y)) {
      if (SD.remove(pendingDeletePath)) {
        Serial.printf("Archivo Vault eliminado: %s\n", pendingDeletePath);
        memset(pendingDeletePath, 0, sizeof(pendingDeletePath)); deleteFailed = false;
        if (pendingDeleteSession) { scanSessionSeeds(); screen = Screen::session_seed_list; }
        else { scanVaultFiles(); screen = Screen::vault_list; }
        focusIndex = 0; drawScreen();
      } else { deleteFailed = true; focusIndex = 0; drawScreen(); }
    }
  } else if (screen == Screen::address_explorer) {
    bool changed = false;
    if (kAddressReceive.contains(x, y) && addressChange != 0) { addressChange = 0; changed = true; }
    else if (kAddressChange.contains(x, y) && addressChange != 1) { addressChange = 1; changed = true; }
    else if (kAddressMinus.contains(x, y) && addressIndex > 0) { --addressIndex; changed = true; }
    else if (kAddressPlus.contains(x, y) && addressIndex < 999999) { ++addressIndex; changed = true; }
    else if (kAddressIndex.contains(x, y)) {
      memset(indexBuffer, 0, sizeof(indexBuffer));
      screen = Screen::address_index_input; focusIndex = 0; drawScreen(); return;
    }
    else if (kAddressProfile.contains(x, y)) {
      publicKeyProfile = (publicKeyProfile + 1) % kPublicProfileCount; changed = true;
    } else if ((kAddressValue.contains(x, y) || kAction.contains(x, y)) && buildAddressQr()) {
      screen = Screen::address_qr; focusIndex = 0; drawScreen(); return;
    } else if (kBack.contains(x, y)) {
      screen = Screen::active_seed; focusIndex = 3; drawScreen(); return;
    }
    if (changed) { updateAddress(); drawAddressExplorer(); }
  } else if (screen == Screen::address_qr) {
    if (kAction.contains(x, y)) { screen = Screen::address_explorer; focusIndex = 6; drawScreen(); }
  } else if (screen == Screen::address_index_input) {
    for (uint8_t i = 0; i < 10; ++i) if (kDigitKey[i].contains(x, y)) {
      const char digit = i == 9 ? '0' : static_cast<char>('1' + i);
      const size_t len = strlen(indexBuffer);
      if (len < 6) { indexBuffer[len] = digit; indexBuffer[len + 1] = '\0'; updateAddressIndexDynamic(); }
      return;
    }
    if (kDigitDelete.contains(x, y) && indexBuffer[0]) {
      indexBuffer[strlen(indexBuffer) - 1] = '\0'; updateAddressIndexDynamic();
    } else if (kAction.contains(x, y) && indexBuffer[0]) {
      uint32_t value = 0;
      for (size_t i = 0; indexBuffer[i]; ++i) value = value * 10 + (indexBuffer[i] - '0');
      addressIndex = value > 999999 ? 999999 : value;
      memset(indexBuffer, 0, sizeof(indexBuffer));
      updateAddress();
      screen = Screen::address_explorer; focusIndex = 3; drawScreen();
    } else if (kBack.contains(x, y)) {
      memset(indexBuffer, 0, sizeof(indexBuffer));
      screen = Screen::address_explorer; focusIndex = 3; drawScreen();
    }
  } else if (screen == Screen::discard_confirm) {
    if (kBack.contains(x, y)) { screen = Screen::active_seed; focusIndex = 4; drawScreen(); }
    else if (kAction.contains(x, y)) {
      const bool anotherActive = discardCurrentSeed();
      screen = anotherActive ? Screen::active_seed : Screen::menu;
      focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::unlock_confirm) {
    if (kBack.contains(x, y)) { screen = Screen::vault_unlock; focusIndex = 1; drawScreen(); }
    else if (kAction.contains(x, y)) {
      if (unlockConfirmIsSession) unlockSessionVault();
      else loadSelectedVault();
    }
  } else if (screen == Screen::scan_qr) {
    const auto p = qrClient.phase();
    if (p == qr_ble::Phase::Failed) {
      if (kBack.contains(x, y)) {
        qrClient.clear(); screen = Screen::menu; focusIndex = 4; drawScreen();
      } else if (kAction.contains(x, y)) {
        beginScanQr();
      }
    } else if (p == qr_ble::Phase::Success) {
      if (kAction.contains(x, y)) {
        qrClient.clear(); screen = Screen::menu; focusIndex = 4; drawScreen();
      }
    } else if (kAction.contains(x, y)) {
      qrClient.cancel(); screen = Screen::menu; focusIndex = 4; drawScreen();
    }
  } else if (screen == Screen::wifi_receive) {
    const auto p = wifiServer.phase();
    if (p == qr_wifi::Phase::Received) {
      if (wifiServer.mode() == qr_wifi::Mode::kSeedText) {
        if (kBack.contains(x, y)) { returnFromWifiReceive(); }
        else if (kAction.contains(x, y)) { beginWifiReceive(qr_wifi::Mode::kSeedText); }
      } else if (txIsPsbt) {
        if (kFirmar.contains(x, y) && fingerprintValid) { beginSignTx(); }
        else if (kDetail.contains(x, y)) { utxoReturnScreen = screen; screen = Screen::utxo_detail; focusIndex = 0; drawScreen(); }
        else if (kBack.contains(x, y)) { returnFromWifiReceive(); }
      } else if (kAction.contains(x, y)) {
        returnFromWifiReceive();
      }
    } else if (p == qr_wifi::Phase::Failed) {
      if (kBack.contains(x, y)) { returnFromWifiReceive(); }
      else if (kAction.contains(x, y)) { beginWifiReceive(wifiServer.mode()); }
    } else if (kAction.contains(x, y)) {
      wifiServer.cancel(); returnFromWifiReceive();
    }
  } else if (screen == Screen::wifi_mode) {
    if (kMenu[0].contains(x, y) && fingerprintValid) { beginWifiReceive(qr_wifi::Mode::kFile); }
    else if (kMenu[1].contains(x, y) && fingerprintValid) { beginWifiReceive(qr_wifi::Mode::kTxText); }
    else if (kMenu[2].contains(x, y)) { beginWifiReceive(qr_wifi::Mode::kSeedText); }
    else if (kBack.contains(x, y)) { returnFromWifiReceive(); }
  } else if (screen == Screen::signed_tx) {
    if (kAction.contains(x, y)) { screen = Screen::signed_mode; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::signed_mode) {
    if (kMenu[0].contains(x, y)) { screen = Screen::signed_tx; focusIndex = 0; drawScreen(); }
    else if (kMenu[1].contains(x, y) && !txIsMultisig) { beginAnimatedQr(); }
    else if (kBack.contains(x, y)) { screen = Screen::menu; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::animated_qr) {
    if (kAction.contains(x, y)) { screen = Screen::signed_mode; focusIndex = 1; drawScreen(); }
  } else if (screen == Screen::tx_review) {
    if (kFirmar.contains(x, y) && fingerprintValid) { beginSignTx(); }
    else if (kDetail.contains(x, y)) { utxoReturnScreen = screen; screen = Screen::utxo_detail; focusIndex = 0; drawScreen(); }
    else if (kBack.contains(x, y)) { screen = Screen::menu; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::utxo_detail) {
    if (kAction.contains(x, y)) { screen = utxoReturnScreen; focusIndex = 1; drawScreen(); }
  } else if (screen == Screen::diagnostics && kBack.contains(x, y)) {
    screen = Screen::menu; focusIndex = 0; drawScreen();
  } else if (screen == Screen::help && kBack.contains(x, y)) {
    screen = Screen::menu; focusIndex = 0; drawScreen();
  } else if (screen == Screen::settings) {
    if (kMenu[0].contains(x, y)) { screen = Screen::settings_lang; focusIndex = 0; drawScreen(); }
    else if (kMenu[1].contains(x, y)) { screen = Screen::settings_timeout; focusIndex = 0; drawScreen(); }
    else if (kMenu[2].contains(x, y)) { screen = Screen::settings_clean; focusIndex = 0; drawScreen(); }
    else if (kMenu[3].contains(x, y)) { screen = Screen::settings_derivation; focusIndex = 0; drawScreen(); }
    else if (kMenu[4].contains(x, y)) { screen = Screen::settings_radio; focusIndex = 0; drawScreen(); }
    else if (kBack.contains(x, y)) { screen = Screen::menu; focusIndex = 5; drawScreen(); }
  } else if (screen == Screen::settings_lang) {
    if (kMenu[0].contains(x, y)) { gSettings.language = 0; lang::set(lang::Lang::EN); saveSettingsNow(); drawSettingsLang(); }
    else if (kMenu[1].contains(x, y)) { gSettings.language = 1; lang::set(lang::Lang::ES); saveSettingsNow(); drawSettingsLang(); }
    else if (kBack.contains(x, y)) { screen = Screen::settings; focusIndex = 0; drawScreen(); }
  } else if (screen == Screen::settings_timeout) {
    if (kBack.contains(x, y)) { screen = Screen::settings; focusIndex = 1; drawScreen(); }
    else for (uint8_t i = 0; i < device_settings::kTimeoutOptionCount; ++i) {
      if (kMenu[i].contains(x, y)) { gSettings.lockTimeoutMs = device_settings::kTimeoutOptions[i]; saveSettingsNow(); drawSettingsTimeout(); return; }
    }
  } else if (screen == Screen::settings_clean) {
    if (kBack.contains(x, y)) { screen = Screen::settings; focusIndex = 2; drawScreen(); }
    else for (uint8_t i = 0; i < device_settings::kCleanOptionCount; ++i) {
      if (kMenu[i].contains(x, y)) { gSettings.seedCleanTimeoutMs = device_settings::kCleanOptions[i]; saveSettingsNow(); drawSettingsClean(); return; }
    }
  } else if (screen == Screen::settings_derivation) {
    if (kBack.contains(x, y)) { screen = Screen::settings; focusIndex = 3; drawScreen(); }
    else for (uint8_t i = 0; i < kPublicProfileCount; ++i) {
      if (kMenu[i].contains(x, y)) { gSettings.defaultProfile = i; saveSettingsNow(); drawSettingsDerivation(); return; }
    }
  } else if (screen == Screen::settings_radio) {
    if (kBack.contains(x, y)) { screen = Screen::settings; focusIndex = 4; drawScreen(); }
  } else if (screen == Screen::multisig_confirm) {
    if (kBack.contains(x, y)) { screen = Screen::menu; focusIndex = 0; drawScreen(); }
    else if (kFirmar.contains(x, y) && fingerprintValid) { beginMultisigSign(); }
  } else if (screen == Screen::tx_history) {
    for (uint8_t i = 0; i < txFileCount; ++i) {
      if (kVaultFiles[i].contains(x, y)) {
        loadPsbtFromFile(txFiles[i]);
        return;
      }
    }
    if (kBack.contains(x, y)) { screen = Screen::menu; focusIndex = 4; drawScreen(); }
  }
}

void activateFocus() {
  if (screen == Screen::menu) click(kMenu[focusIndex].x + 5, kMenu[focusIndex].y + 5);
  else if (screen == Screen::active_seed) click(kActiveMenu[focusIndex].x + 5, kActiveMenu[focusIndex].y + 5);
  else if (screen == Screen::vault_actions) click(kActiveMenu[focusIndex].x + 5, kActiveMenu[focusIndex].y + 5);
  else if (screen == Screen::seed_switcher) {
    const Rect& r = focusIndex < loadedSeedCount ? kVaultFiles[focusIndex] : kBack;
    click(r.x + 5, r.y + 5);
  }
  else if (screen == Screen::passphrase_input) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  }
  else if (screen == Screen::backup_seed) click(kActiveMenu[focusIndex].x + 5, kActiveMenu[focusIndex].y + 5);
  else if (screen == Screen::length) {
    const Rect& r = focusIndex == 0 ? kChoose12 : focusIndex == 1 ? kChoose24 : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::keyboard) {
    const Rect& r = focusIndex == 0 ? kBack : kAction; click(r.x + 5, r.y + 5);
  } else if (screen == Screen::review) {
    const Rect& r = focusIndex == 0 ? kQrPrevious : focusIndex == 1 ? kQrBack : kQrNext;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::plain_qr) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::seedqr) {
    const Rect& r = focusIndex == 0 ? kQrPrevious : focusIndex == 1 ? kQrBack : kQrNext;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::public_key) {
    const Rect& r = focusIndex == 0 ? kPublicQr : focusIndex == 1 ? kQrPrevious :
                    focusIndex == 2 ? kQrBack : kQrNext;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::public_key_qr) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::entropy_length) {
    const Rect& r = focusIndex == 0 ? kChoose12 : focusIndex == 1 ? kChoose24 :
                    focusIndex == 2 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::dice) {
    const Rect& r = focusIndex == 0 ? kDiceReset : focusIndex == 1 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::entropy) {
    const Rect& r = focusIndex == 0 ? kBack : kEntropyCreate;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::security_warning) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::vault_password) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::vault_label) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::vault_list) {
    const Rect& r = focusIndex < vaultFileCount ? kVaultFiles[focusIndex] :
                    focusIndex == vaultFileCount ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::vault_unlock) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::vault_loaded) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::session_menu) {
    click(kMenu[focusIndex].x + 5, kMenu[focusIndex].y + 5);
  } else if (screen == Screen::session_meta_list) {
    const Rect& r = focusIndex < sessionMetaCount ? kVaultFiles[focusIndex] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::session_seed_list) {
    Rect r;
    if (focusIndex < sessionSeedCount) r = kVaultFiles[focusIndex];
    else if (sessionDeleteMode) r = focusIndex == sessionSeedCount ? kSessionBack : kSessionAction;
    else if (focusIndex == sessionSeedCount) r = kSessionNewVault;
    else if (focusIndex == sessionSeedCount + 1) r = kSessionNewEntropy;
    else if (focusIndex == sessionSeedCount + 2) r = kSessionNewRam;
    else if (focusIndex == sessionSeedCount + 3) r = kSessionBack;
    else r = kSessionAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::delete_confirm) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::vault_result) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::address_explorer) {
    const Rect& r = focusIndex == 0 ? kAddressReceive :
                    focusIndex == 1 ? kAddressChange :
                    focusIndex == 2 ? kAddressMinus :
                    focusIndex == 3 ? kAddressPlus :
                    focusIndex == 4 ? kAddressProfile :
                    focusIndex == 5 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::address_qr) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::address_index_input) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::discard_confirm) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::unlock_confirm) {
    const Rect& r = focusIndex == 0 ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::scan_qr) {
    const auto p = qrClient.phase();
    const Rect& r = (p == qr_ble::Phase::Failed && focusIndex == 0) ? kBack : kAction;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::wifi_receive) {
    const auto p = wifiServer.phase();
    const Rect* r = &kAction;
    if (p == qr_wifi::Phase::Failed && focusIndex == 0) r = &kBack;
    else if (p == qr_wifi::Phase::Received &&
             wifiServer.mode() == qr_wifi::Mode::kSeedText) {
      r = focusIndex == 0 ? &kBack : &kAction;
    }
    else if (p == qr_wifi::Phase::Received && txIsPsbt) {
      if (focusIndex == 0) r = &kBack;
      else if (focusIndex == 1) r = &kDetail;
      else r = &kFirmar;
    }
    click(r->x + 5, r->y + 5);
  } else if (screen == Screen::wifi_mode) {
    const Rect& r = focusIndex == 0 ? kMenu[0] :
                    focusIndex == 1 ? kMenu[1] :
                    focusIndex == 2 ? kMenu[2] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::settings) {
    const Rect& r = focusIndex == 0 ? kMenu[0] : focusIndex == 1 ? kMenu[1] :
                    focusIndex == 2 ? kMenu[2] : focusIndex == 3 ? kMenu[3] :
                    focusIndex == 4 ? kMenu[4] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::settings_lang) {
    const Rect& r = focusIndex == 0 ? kMenu[0] : focusIndex == 1 ? kMenu[1] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::settings_timeout) {
    const Rect& r = focusIndex < device_settings::kTimeoutOptionCount ? kMenu[focusIndex] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::settings_clean) {
    const Rect& r = focusIndex < device_settings::kCleanOptionCount ? kMenu[focusIndex] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::settings_derivation) {
    const Rect& r = focusIndex < kPublicProfileCount ? kMenu[focusIndex] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::settings_radio) {
    click(kBack.x + 5, kBack.y + 5);
  } else if (screen == Screen::multisig_confirm) {
    const Rect& r = focusIndex == 0 ? kBack : kFirmar;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::tx_history) {
    const Rect& r = focusIndex < txFileCount ? kVaultFiles[focusIndex] : kBack;
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::signed_tx) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::signed_mode) {
    const Rect& r = focusIndex == 0 ? kMenu[0] : (focusIndex == 1 ? kMenu[1] : kBack);
    click(r.x + 5, r.y + 5);
  } else if (screen == Screen::animated_qr) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::tx_review) {
    const Rect* r = focusIndex == 0 ? &kBack : (focusIndex == 1 ? &kDetail : &kFirmar);
    click(r->x + 5, r->y + 5);
  } else if (screen == Screen::utxo_detail) {
    click(kAction.x + 5, kAction.y + 5);
  } else if (screen == Screen::diagnostics) click(kBack.x + 5, kBack.y + 5);
  else if (screen == Screen::help) click(kBack.x + 5, kBack.y + 5);
}

}  // namespace

void setup() {
  Serial.begin(115200);
  M5.begin();
  M5.EPD.SetRotation(M5EPD_Driver::ROTATE_90);
  M5.TP.SetRotation(GT911::ROTATE_90);
  pinMode(kRockerLeftPin, INPUT);
  pinMode(kRockerPressPin, INPUT);
  pinMode(kRockerRightPin, INPUT);
  M5.EPD.Clear(true);
  if (!page.createCanvas(kWidth, kHeight)) return;
  Serial.printf("M5Paper Seed Workstation - %s\n", kVersion);
  fingerprintSelfTest = bitcoin_fingerprint::self_test();
  Serial.printf("Fingerprint BIP32 self-test: %s\n",
                fingerprintSelfTest ? "OK" : "ERROR");
  Serial.printf("PBKDF2-HMAC-SHA256 self-test: %s\n",
                encrypted_seed_store::self_test() ? "OK" : "ERROR");
  Serial.printf("PSBT parser self-test: %s\n",
                psbt::self_test() ? "OK" : "ERROR");
  Serial.printf("ECDSA (RFC6979) self-test: %s\n",
                tx_sign::self_test() ? "OK" : "ERROR");
  hdSelfTest = bitcoin_hd::self_test() && bitcoin_hd::self_test_passphrase();
  Serial.printf("BIP32 xpub/zpub self-test: %s\n", hdSelfTest ? "OK" : "ERROR");
  addressBip84SelfTest = bitcoin_address::self_test_bip84();
  Serial.printf("Bitcoin address BIP84 self-test: %s\n",
                addressBip84SelfTest ? "OK" : "ERROR");
  gSettings = device_settings::load();
  lang::set(gSettings.language == 1 ? lang::Lang::ES : lang::Lang::EN);
  lastUserActivity = millis();
  drawScreen();
}

void loop() {
  checkSerialCommand();

  if (screen == Screen::locked || screen == Screen::screensaver) {
    // Pantalla estatica (e-ink): sin animaciones para no consumir bateria.
  } else if (gSettings.lockTimeoutMs != 0 &&
             static_cast<uint32_t>(millis() - lastUserActivity) >= gSettings.lockTimeoutMs) {
    enterScreensaver();
    return;
  }

  if (screen == Screen::animated_qr && bbqrTotalParts > 1 &&
      static_cast<uint32_t>(millis() - bbqrLastFrameMs) >= 1000) {
    bbqrLastFrameMs = millis();
    bbqrIndex = (bbqrIndex + 1) % bbqrTotalParts;
    drawAnimatedQr();
  }
  qrClient.update();
  if (screen == Screen::scan_qr) {
    const auto qp = qrClient.phase();
    if (qp == qr_ble::Phase::Cancelled || qp == qr_ble::Phase::Idle) {
      screen = Screen::menu; focusIndex = 4; drawScreen();
    } else {
      renderScanQrDynamic();
    }
  } else if (scanQrActive()) {
    qrClient.cancel();
  }

  wifiServer.update();
  if (screen == Screen::wifi_receive) {
    const auto wp = wifiServer.phase();
    if (wp == qr_wifi::Phase::Cancelled || wp == qr_wifi::Phase::Idle) {
      screen = Screen::menu; focusIndex = 4; drawScreen();
    } else if (wp == qr_wifi::Phase::Received && !wifiResultShown) {
      wifiResultShown = true;
      if (wifiServer.mode() == qr_wifi::Mode::kSeedText) {
        if (loadSeedText(wifiServer.data())) {
          wifiServer.clear();
          newSeedIntent = NewSeedIntent::none;
          screen = Screen::review;
          focusIndex = 0;
          drawScreen();
        } else {
          drawWifiReceive();
        }
      } else {
        txIsPsbt = psbt::tryParsePsbt(wifiServer.data(), parsedTx);
        if (txIsPsbt) {
          saveReceivedPsbt(wifiServer.data());
          txIsMultisig = multisig::detect(parsedTx, txMsInfo);
          if (txIsMultisig) {
            wifiServer.clear();
            screen = Screen::multisig_confirm; focusIndex = 0; drawMultisigConfirm();
          } else {
            drawWifiReceive();
          }
        } else drawWifiReceive();
      }
    }
  }

  const uint32_t cleanMs = gSettings.seedCleanTimeoutMs;
  const bool hasSeed = fingerprintValid || sessionUnlocked;
  if (cleanMs != 0 && hasSeed &&
      static_cast<uint32_t>(millis() - lastUserActivity) >= cleanMs) {
    Serial.println("Limpieza de seed por inactividad");
    lastWarnSecond = 0;
    if (sessionUnlocked) lockSessionVault();
    else discardActiveSeed();
    screen = Screen::menu; focusIndex = 0; drawScreen();
    return;
  }
  if (cleanMs != 0 && hasSeed) {
    const uint32_t remaining = cleanMs -
        static_cast<uint32_t>(millis() - lastUserActivity);
    if (remaining <= kSessionTimeoutWarnMs) {
      if (screen != Screen::session_lock_warning) {
        sessionLockReturn = screen;
        screen = Screen::session_lock_warning;
        lastWarnSecond = 0;
        drawSessionLockWarning();
      } else {
        const uint32_t sec = remaining / 1000 + 1;
        if (sec != lastWarnSecond) {
          lastWarnSecond = sec;
          drawSessionLockWarning();
        }
      }
    } else {
      lastWarnSecond = 0;
      if (screen == Screen::session_lock_warning) {
        screen = sessionLockReturn; focusIndex = 0; drawScreen();
      }
    }
  }
  static int oldLeft = HIGH, oldPress = HIGH, oldRight = HIGH;
  static uint32_t lastRocker = 0;
  const int left = digitalRead(kRockerLeftPin);
  const int press = digitalRead(kRockerPressPin);
  const int right = digitalRead(kRockerRightPin);
  if ((screen == Screen::locked || screen == Screen::screensaver) &&
      (left == LOW || right == LOW || press == LOW)) {
    if (millis() - lastRocker >= 120) {
      lastRocker = millis(); lastUserActivity = millis();
      if (screen == Screen::screensaver) { screen = screensaverReturn; }
      else { screen = Screen::menu; }
      focusIndex = 0; drawScreen();
    }
  } else if (screen == Screen::session_lock_warning &&
      (left == LOW || right == LOW || press == LOW)) {
    if (millis() - lastRocker >= 120) {
      lastRocker = millis(); lastUserActivity = millis();
      screen = sessionLockReturn; focusIndex = 0; drawScreen();
    }
  } else if (millis() - lastRocker >= 120) {
    // NOTA: la palanca va "invertida" a proposito: IZQUIERDA avanza y DERECHA
    // retrocede. Es el comportamiento historico del dispositivo; NO "corregir".
    if (left == LOW && oldLeft == HIGH) { lastRocker = millis(); lastUserActivity = millis(); moveFocus(1); }
    else if (right == LOW && oldRight == HIGH) { lastRocker = millis(); lastUserActivity = millis(); moveFocus(-1); }
    else if (press == LOW && oldPress == HIGH) { lastRocker = millis(); lastUserActivity = millis(); activateFocus(); }
  }
  oldLeft = left; oldPress = press; oldRight = right;

  static bool wasDown = false;
  static int tx = -1, ty = -1;
  if (M5.TP.available()) {
    M5.TP.update();
    const bool down = !M5.TP.isFingerUp();
    if (down) {
      tx = M5.TP.readFingerX(0); ty = M5.TP.readFingerY(0);
      lastUserActivity = millis();
      static uint32_t lastEntropySample = 0;
      if (screen == Screen::entropy && millis() - lastEntropySample >= 12) {
        lastEntropySample = millis();
        entropyTouch(tx, ty);
      }
    } else if (wasDown) {
      lastUserActivity = millis();
      if (screen == Screen::locked) {
        screen = Screen::menu; focusIndex = 0; drawScreen();
      } else if (screen == Screen::screensaver) {
        screen = screensaverReturn; focusIndex = 0; drawScreen();
      } else if (screen == Screen::session_lock_warning) {
        screen = sessionLockReturn; focusIndex = 0; drawScreen();
      } else {
        click(tx, ty);
      }
      entropyLastX = entropyLastY = -1;
    }
    wasDown = down;
    M5.TP.flush();
  }
  if ((screen == Screen::vault_password || screen == Screen::vault_unlock) &&
      vaultRevealUntil &&
      static_cast<int32_t>(millis() - vaultRevealUntil) >= 0) {
    vaultRevealUntil = 0;
    updateVaultPasswordDynamic();
    updateButton(kVaultReveal, "MOSTRAR 3 SEG.",
                 strlen(activeVaultPassword()) > 0, false, Icon::eye, UPDATE_MODE_A2);
  }
  if (toastUntil && static_cast<int32_t>(millis() - toastUntil) >= 0) {
    toastUntil = 0; toastMessage[0] = '\0';
    drawScreen();
  }
  delay(8);
}
