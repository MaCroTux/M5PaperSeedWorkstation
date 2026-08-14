#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include "ble_key.hpp"
#include "vault_key.hpp"

// Cliente BLE (M5Paper) de la llave M5Core2.
//
// EMPAREJAR: scan -> connect -> leer pk (PAIR_PUBKEY) -> escribir PAIR_CONFIRM
//            -> confirmar en el Core2 -> guardar pk.
// SET PIN:   scan -> connect -> escribir SET_PIN -> esperar a que el usuario
//            fije el PIN en el Core2 (UNLOCK_STATUS authorized).
// DESBLOQUEAR: scan -> connect -> generar (e_sess,E_sess) -> escribir
//            E_sess || ECIES(M) -> el Core2 pide PIN y descifra -> recibir
//            AES-GCM(M, K_sess) -> descifrar la maestra.
//
// La maestra descifrada queda en master() y debe limpiarse tras usarla.

namespace ble_key {

class BleKeyClient {
public:
  enum class Phase : uint8_t {
    Idle, Scanning, Connecting,
    PairRequesting, Paired,
    SetPinRequesting, SetPinDone,
    UnlockRequesting, Unlocked,
    Denied, Failed, Cancelled
  };
  enum class Error : uint8_t {
    None, BleInit, ScanTimeout, ConnectFailed, ServiceNotFound,
    SubscribeFailed, Disconnected, Timeout, WriteFailed, BadResponse
  };

  BleKeyClient();
  ~BleKeyClient();

  void startPairing();
  void startSetPin();
  void startUnlock(const uint8_t blob[vault_2fa::kBlobSize]);
  void cancel();
  void update();
  void clear();

  Phase phase() const { return phase_; }
  Error error() const { return error_; }
  bool paired() const { return phase_ == Phase::Paired; }
  bool setPinDone() const { return phase_ == Phase::SetPinDone; }
  bool unlocked() const { return phase_ == Phase::Unlocked; }
  bool hasMaster() const { return masterReady_; }
  const uint8_t* master() const { return master_; }
  const char* statusText();

private:
  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }
  void beginScan();
  void teardown();

  void onScanResult(NimBLEAdvertisedDevice* d);
  void onConnectCallback(NimBLEClient* c);
  void onDisconnectCallback(NimBLEClient* c);
  void onPairStatusNotify(uint8_t* data, size_t len);
  void onUnlockStatusNotify(uint8_t* data, size_t len);
  void onUnlockRespNotify(uint8_t* data, size_t len);

  Phase phase_ = Phase::Idle;
  Error error_ = Error::None;
  uint8_t mode_ = 0;  // 0 none, 1 pair, 2 setpin, 3 unlock

  SemaphoreHandle_t mux_ = nullptr;
  uint8_t pk_[kPubKeySize] = {};

  uint8_t eSess_[kKeySize] = {};
  uint8_t blob_[kPubKeySize + vault_2fa::kBlobSize] = {};  // E_sess || ECIES(M)
  uint8_t master_[vault_2fa::kMasterSize] = {};
  bool masterReady_ = false;

  bool found_ = false;
  std::string foundAddr_;
  uint8_t foundType_ = 0;
  bool connected_ = false;
  bool disconnected_ = false;

  bool pairStatusRcvd_ = false;
  uint8_t pairStatus_ = 0;
  bool unlockStatusRcvd_ = false;
  uint8_t unlockStatus_ = 0;
  bool unlockRespRcvd_ = false;
  uint8_t unlockResp_[kEciesNonceSize + vault_2fa::kMasterSize + kGcmTagSize] = {};

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
