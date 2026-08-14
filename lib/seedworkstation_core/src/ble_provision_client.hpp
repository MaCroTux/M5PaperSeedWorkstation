#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include "ble_provision.hpp"

// Cliente BLE (M5Paper) para provisionar una seed al M5Stick.
//
// FLUJO: scan -> connect -> leer pk del M5Stick -> ECIES(seed) -> escribir
//        PROV_REQ -> el M5Stick pide confirmacion fisica -> recibir
//        PROV_STATUS (accepted/denied/error).
//
// La seed (mnemonic + fingerprint) se cifra en transito y nunca viaja en claro.

namespace ble_provision {

class BleProvisionClient {
public:
  enum class Phase : uint8_t {
    Idle, Scanning, Connecting, AwaitingConfirm, Provisioned,
    Denied, Failed, Cancelled
  };
  enum class Error : uint8_t {
    None, BleInit, ScanTimeout, ConnectFailed, ServiceNotFound,
    SubscribeFailed, Disconnected, Timeout, WriteFailed, BadResponse
  };

  BleProvisionClient();
  ~BleProvisionClient();

  void start(const uint16_t* words, uint8_t count, const uint8_t fingerprint[4]);
  void cancel();
  void update();
  void clear();

  Phase phase() const { return phase_; }
  Error error() const { return error_; }
  bool provisioned() const { return phase_ == Phase::Provisioned; }
  const char* statusText();

private:
  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }
  void beginScan();
  void teardown();

  void onScanResult(NimBLEAdvertisedDevice* d);
  void onConnectCallback(NimBLEClient* c);
  void onDisconnectCallback(NimBLEClient* c);
  void onStatusNotify(uint8_t* data, size_t len);

  Phase phase_ = Phase::Idle;
  Error error_ = Error::None;

  SemaphoreHandle_t mux_ = nullptr;
  uint8_t payload_[kPayloadSize] = {};
  size_t payloadLen_ = 0;
  uint8_t pk_[ble_key::kPubKeySize] = {};

  bool found_ = false;
  std::string foundAddr_;
  uint8_t foundType_ = 0;
  bool connected_ = false;
  bool disconnected_ = false;

  bool statusRcvd_ = false;
  uint8_t status_ = 0;

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

}  // namespace ble_provision
