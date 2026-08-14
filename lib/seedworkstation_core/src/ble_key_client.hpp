#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include "ble_key.hpp"

// Cliente BLE (M5Paper) de la llave criptografica.
//
// Desbloqueo: scan -> connect -> suscribir AUTH_RESPONSE/AUTH_STATUS ->
// challenge aleatorio -> verificar HMAC-SHA256(K_pair, challenge).
//
// Emparejamiento: scan -> connect -> suscribir PAIR_RESPONSE/PAIR_STATUS ->
// generar par efimero -> escribir PAIR_PUBKEY -> recibir pub del Core2 ->
// derivar K_pair = SHA256(x(ECDH(p_m, Q_core2))||tag) -> guardar en NVS.
// K_pair jamas viaja en claro.
//
// Toda la logica de conexion se ejecuta desde update() (loop). Las callbacks
// de NimBLE NO hacen cripto ni dibujan; solo guardan datos bajo mutex.

namespace ble_key {

class BleKeyClient {
public:
  enum class Phase : uint8_t {
    Idle, Scanning, Connecting, Requesting,
    Verified, Paired, Denied, Failed, Cancelled
  };
  enum class Error : uint8_t {
    None, BleInit, ScanTimeout, ConnectFailed, ServiceNotFound,
    SubscribeFailed, Disconnected, Timeout, WriteFailed, BadResponse
  };

  BleKeyClient();
  ~BleKeyClient();

  void start();       // desbloqueo (carga K_pair de NVS) + scan
  void startPairing();// emparejamiento + scan
  void cancel();
  void update();      // llamar desde loop()
  void clear();

  Phase phase() const { return phase_; }
  Error error() const { return error_; }
  bool verified() const { return phase_ == Phase::Verified; }
  bool paired() const { return phase_ == Phase::Paired; }
  bool pairing() const { return pairingMode_; }
  const char* statusText();

private:
  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }
  void beginScan();
  void teardown();

  void onScanResult(NimBLEAdvertisedDevice* d);
  void onConnectCallback(NimBLEClient* c);
  void onDisconnectCallback(NimBLEClient* c);
  void onResponseNotify(uint8_t* data, size_t len);
  void onStatusNotify(uint8_t* data, size_t len);
  void onPairResponseNotify(uint8_t* data, size_t len);
  void onPairStatusNotify(uint8_t* data, size_t len);

  Phase phase_ = Phase::Idle;
  Error error_ = Error::None;
  bool pairingMode_ = false;

  SemaphoreHandle_t mux_ = nullptr;
  uint8_t key_[kKeySize] = {};        // K_pair (desbloqueo)
  uint8_t challenge_[kChallengeSize] = {};

  uint8_t ephPriv_[kKeySize] = {};    // par efimero (emparejamiento)
  uint8_t ephPub_[kPubKeySize] = {};
  uint8_t theirPub_[kPubKeySize] = {};

  bool found_ = false;
  std::string foundAddr_;
  uint8_t foundType_ = 0;
  bool connected_ = false;
  bool disconnected_ = false;

  bool responseReceived_ = false;
  uint8_t response_[kResponseSize] = {};
  bool statusReceived_ = false;
  Status status_ = kStatusIdle;

  bool pairResponseReceived_ = false;
  bool pairStatusReceived_ = false;
  PairStatus pairStatus_ = kPairIdle;

  NimBLEScan* scan_ = nullptr;
  NimBLEClient* client_ = nullptr;
  bool bleOn_ = false;
  bool scanning_ = false;

  uint32_t scanStartMs_ = 0;
  uint32_t requestStartMs_ = 0;

  class ScanCallbacks;
  class ClientCallbacks;
  ScanCallbacks* scanCallbacks_ = nullptr;
  ClientCallbacks* clientCallbacks_ = nullptr;
};

}  // namespace ble_key
