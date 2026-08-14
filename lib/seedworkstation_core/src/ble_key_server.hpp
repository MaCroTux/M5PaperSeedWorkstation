#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include "ble_key.hpp"
#include "vault_key.hpp"

// Servidor BLE (M5Core2) = LLAVE que guarda la clave privada sk, protegida por
// PIN. El M5Paper cifra la maestra del vault con la publica pk del Core2 y, al
// desbloquear, pide al Core2 que la descifre (tras introducir el PIN).
//
// Caracteristicas:
//   PAIR_PUBKEY   (read)    pk del Core2 (65 bytes, publica).
//   PAIR_CONFIRM  (write)   el M5Paper pide confirmar emparejamiento (1 byte).
//   PAIR_STATUS   (notify)  estado del emparejamiento.
//   SET_PIN       (write)   el M5Paper pide fijar el PIN (1 byte).
//   UNLOCK_REQ    (write)   E_sess(65) || ECIES(M)(125) = 190 bytes.
//   UNLOCK_RESP   (notify)  AES-GCM(M, K_sess) = nonce||ct||tag (60 bytes).
//   UNLOCK_STATUS (notify)  1 byte: estado del desbloqueo/PIN.
//   DEVICE_INFO   (read)
//
// sk se guarda cifrada en NVS ("ksk") bajo K_pin = PBKDF2(PIN). 3 PINs fallidos
// borran la sk (hay que re-migrar el vault con la contrasena).

namespace ble_key {

class BleKeyServer {
public:
  enum class State : uint8_t { Idle, Requested, Authorized, Denied, Timeout };
  enum class PairState : uint8_t { Idle, Requested, Authorized, Denied, Timeout };
  enum class PinState : uint8_t { Idle, SetEntry, SetConfirm, UnlockEntry,
                                  Done, Failed };

  BleKeyServer();
  ~BleKeyServer();

  bool begin();
  void update();

  void allowPairing();
  void denyPairing();

  void pinDigit(char d);
  void pinBackspace();
  void pinSubmit();
  void pinCancel();

  State state() const { return state_; }
  PairState pairState() const { return pairState_; }
  PinState pinState() const { return pinState_; }
  bool hasPin() const { return vault_2fa::hasEncryptedSk(); }
  const char* pinBuffer() const { return pinBuffer_; }

private:
  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }
  void notifyPairStatus(PairStatus s);
  void notifyUnlockStatus(uint8_t s);

  void onPairConfirmWrite(NimBLECharacteristic* c);
  void onSetPinWrite(NimBLECharacteristic* c);
  void onUnlockWrite(NimBLECharacteristic* c);
  void onClientConnect(NimBLEServer* s);
  void onClientDisconnect(NimBLEServer* s);

  bool unlockSkWithPin();
  void processUnlock();
  void doSetPin();
  void wipeSk();

  SemaphoreHandle_t mux_ = nullptr;

  State state_ = State::Idle;
  PairState pairState_ = PairState::Idle;
  PinState pinState_ = PinState::Idle;

  uint8_t sk_[kKeySize] = {};      // privada (en RAM solo tras desbloquear)
  uint8_t pub_[kPubKeySize] = {};  // publica
  bool hasPaired_ = false;

  uint32_t pairStartMs_ = 0;
  uint32_t pairResultStartMs_ = 0;

  uint8_t unlockReq_[kPubKeySize + vault_2fa::kBlobSize] = {};
  bool unlockReqReady_ = false;
  uint32_t requestStartMs_ = 0;
  uint32_t resultStartMs_ = 0;

  char pinBuffer_[7] = {};
  char pinFirst_[7] = {};
  uint8_t pinFails_ = 0;

  NimBLEServer* server_ = nullptr;
  NimBLECharacteristic* pairPubChar_ = nullptr;      // READ
  NimBLECharacteristic* pairConfirmChar_ = nullptr;  // WRITE
  NimBLECharacteristic* pairStatusChar_ = nullptr;   // NOTIFY
  NimBLECharacteristic* setPinChar_ = nullptr;       // WRITE
  NimBLECharacteristic* unlockReqChar_ = nullptr;    // WRITE
  NimBLECharacteristic* unlockRespChar_ = nullptr;   // NOTIFY
  NimBLECharacteristic* unlockStatusChar_ = nullptr; // NOTIFY
  NimBLECharacteristic* infoChar_ = nullptr;         // READ

  class ServerCallbacks;
  class PairCallbacks;
  class SetPinCallbacks;
  class UnlockCallbacks;
  ServerCallbacks* serverCallbacks_ = nullptr;
  PairCallbacks* pairCallbacks_ = nullptr;
  SetPinCallbacks* setPinCallbacks_ = nullptr;
  UnlockCallbacks* unlockCallbacks_ = nullptr;
};

}  // namespace ble_key
