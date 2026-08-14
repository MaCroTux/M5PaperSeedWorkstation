#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include "ble_key.hpp"

// Servidor BLE (M5Core2) de la llave criptografica.
//
// Expone el servicio "M5 Vault Key" con:
//   AUTH_CHALLENGE   (write)   challenge de 32 bytes (desbloqueo).
//   AUTH_RESPONSE    (notify)  response = HMAC(K_pair, challenge).
//   AUTH_STATUS      (notify)  1 byte: estado del desbloqueo.
//   PAIR_PUBKEY      (write)   clave publica efimera del M5Paper (33 bytes).
//   PAIR_RESPONSE    (notify)  clave publica del Core2 (33 bytes) al autorizar.
//   PAIR_STATUS      (notify)  1 byte: estado del emparejamiento.
//   DEVICE_INFO      (read)    identificador legible.
//
// Identidad: el Core2 guarda una privada de largo plazo P_core2 (NVS "kpriv").
// Al autorizar un emparejamiento deriva K_pair = SHA256(x(ECDH(P_core2, Q_m))||tag)
// y la guarda (NVS "kpair"). K_pair es lo que se usa para el HMAC de desbloqueo.
//
// Nada de esto responde automaticamente: challenge y emparejamiento requieren
// que la UI llame a allow()/allowPairing() tras la confirmacion fisica.

namespace ble_key {

class BleKeyServer {
public:
  enum class State : uint8_t { Idle, Requested, Authorized, Denied, Timeout };
  enum class PairState : uint8_t { Idle, Requested, Authorized, Denied, Timeout };

  BleKeyServer();
  ~BleKeyServer();

  bool begin();
  void update();
  void allow();
  void deny();
  void allowPairing();
  void denyPairing();

  State state() const { return state_; }
  PairState pairState() const { return pairState_; }
  bool hasPendingRequest() const { return state_ == State::Requested; }
  bool hasPendingPairRequest() const { return pairState_ == PairState::Requested; }
  bool hasPaired() const { return hasPaired_; }

private:
  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }
  void notifyStatus(Status s);
  void notifyPairStatus(PairStatus s);

  void onChallengeWrite(NimBLECharacteristic* c);
  void onPairPubWrite(NimBLECharacteristic* c);
  void onClientConnect(NimBLEServer* s);
  void onClientDisconnect(NimBLEServer* s);

  SemaphoreHandle_t mux_ = nullptr;

  State state_ = State::Idle;
  PairState pairState_ = PairState::Idle;

  uint8_t priv_[kKeySize] = {};      // P_core2 (largo plazo)
  uint8_t pub_[kPubKeySize] = {};    // Q_core2
  uint8_t kpair_[kKeySize] = {};     // K_pair derivada
  bool hasPaired_ = false;

  uint8_t challenge_[kChallengeSize] = {};
  bool challengeReady_ = false;
  uint32_t requestStartMs_ = 0;
  uint32_t resultStartMs_ = 0;

  uint8_t pairPub_[kPubKeySize] = {};
  bool pairPubReady_ = false;
  uint32_t pairStartMs_ = 0;
  uint32_t pairResultStartMs_ = 0;

  NimBLEServer* server_ = nullptr;
  NimBLECharacteristic* challengeChar_ = nullptr;
  NimBLECharacteristic* responseChar_ = nullptr;
  NimBLECharacteristic* statusChar_ = nullptr;
  NimBLECharacteristic* pairPubChar_ = nullptr;
  NimBLECharacteristic* pairResponseChar_ = nullptr;
  NimBLECharacteristic* pairStatusChar_ = nullptr;
  NimBLECharacteristic* infoChar_ = nullptr;

  class ServerCallbacks;
  class ChallengeCallbacks;
  class PairCallbacks;
  ServerCallbacks* serverCallbacks_ = nullptr;
  ChallengeCallbacks* challengeCallbacks_ = nullptr;
  PairCallbacks* pairCallbacks_ = nullptr;
};

}  // namespace ble_key
