#include "ble_key_client.hpp"

namespace ble_key {

namespace {
constexpr uint32_t kScanTimeoutMs = 15000;
constexpr size_t kUnlockReqSize = kPubKeySize + vault_2fa::kBlobSize;
}

class BleKeyClient::ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
public:
  explicit ScanCallbacks(BleKeyClient* c) : client(c) {}
  void onResult(NimBLEAdvertisedDevice* d) override { client->onScanResult(d); }
private:
  BleKeyClient* client;
};

class BleKeyClient::ClientCallbacks : public NimBLEClientCallbacks {
public:
  explicit ClientCallbacks(BleKeyClient* c) : client(c) {}
  void onConnect(NimBLEClient* c) override { client->onConnectCallback(c); }
  void onDisconnect(NimBLEClient* c) override { client->onDisconnectCallback(c); }
private:
  BleKeyClient* client;
};

BleKeyClient::BleKeyClient() {
  mux_ = xSemaphoreCreateMutex();
  scanCallbacks_ = new ScanCallbacks(this);
  clientCallbacks_ = new ClientCallbacks(this);
}

BleKeyClient::~BleKeyClient() {
  teardown();
  delete scanCallbacks_;
  delete clientCallbacks_;
  if (mux_) vSemaphoreDelete(mux_);
  mux_ = nullptr;
}

void BleKeyClient::startPairing() {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting) return;
  teardown();
  mode_ = 1;
  lock();
  found_ = connected_ = disconnected_ = false;
  pairStatusRcvd_ = unlockStatusRcvd_ = unlockRespRcvd_ = false;
  unlock();
  error_ = Error::None;
  beginScan();
}

void BleKeyClient::startSetPin() {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting) return;
  teardown();
  mode_ = 2;
  lock();
  found_ = connected_ = disconnected_ = false;
  pairStatusRcvd_ = unlockStatusRcvd_ = unlockRespRcvd_ = false;
  unlock();
  error_ = Error::None;
  beginScan();
}

void BleKeyClient::startUnlock(const uint8_t blob[vault_2fa::kBlobSize]) {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting) return;
  teardown();
  mode_ = 3;
  if (!loadStoredPk(pk_) || !generateKeyPair(eSess_, blob_ /* E_sess */)) {
    phase_ = Phase::Failed;
    error_ = Error::BleInit;
    return;
  }
  memcpy(blob_ + kPubKeySize, blob, vault_2fa::kBlobSize);
  masterReady_ = false;
  memset(master_, 0, sizeof(master_));
  lock();
  found_ = connected_ = disconnected_ = false;
  pairStatusRcvd_ = unlockStatusRcvd_ = unlockRespRcvd_ = false;
  unlock();
  error_ = Error::None;
  beginScan();
}

void BleKeyClient::beginScan() {
  Serial.println("[BLEKEY] scanning");
  NimBLEDevice::init("M5Paper-Key");
  bleOn_ = true;
  scan_ = NimBLEDevice::getScan();
  scan_->setActiveScan(true);
  scan_->setInterval(100);
  scan_->setWindow(99);
  scan_->setAdvertisedDeviceCallbacks(scanCallbacks_, false);
  scanning_ = scan_->start(0, nullptr, false);
  scanStartMs_ = millis();
  phase_ = Phase::Scanning;
}

void BleKeyClient::cancel() {
  if (phase_ == Phase::Idle || phase_ == Phase::Cancelled) return;
  teardown();
  phase_ = Phase::Cancelled;
}

void BleKeyClient::clear() {
  teardown();
  wipe(pk_, sizeof(pk_));
  wipe(eSess_, sizeof(eSess_));
  wipe(blob_, sizeof(blob_));
  wipe(master_, sizeof(master_));
  masterReady_ = false;
  error_ = Error::None;
  phase_ = Phase::Idle;
  mode_ = 0;
}

void BleKeyClient::onScanResult(NimBLEAdvertisedDevice* device) {
  if (found_) return;
  if (device->haveName() && device->getName() == kDeviceName) {
    lock();
    found_ = true;
    foundAddr_ = device->getAddress().toString();
    foundType_ = device->getAddress().getType();
    unlock();
    Serial.println("[BLEKEY] Core2 found");
  }
}

void BleKeyClient::onConnectCallback(NimBLEClient*) {
  lock(); connected_ = true; disconnected_ = false; unlock();
}

void BleKeyClient::onDisconnectCallback(NimBLEClient*) {
  lock(); disconnected_ = true; connected_ = false; unlock();
  Serial.println("[BLEKEY] disconnected");
}

void BleKeyClient::onPairStatusNotify(uint8_t* data, size_t len) {
  if (len < 1) return;
  lock(); pairStatus_ = data[0]; pairStatusRcvd_ = true; unlock();
  Serial.printf("[BLEKEY] pair status=%u\n", static_cast<unsigned>(data[0]));
}

void BleKeyClient::onUnlockStatusNotify(uint8_t* data, size_t len) {
  if (len < 1) return;
  lock(); unlockStatus_ = data[0]; unlockStatusRcvd_ = true; unlock();
  Serial.printf("[BLEKEY] unlock status=%u\n", static_cast<unsigned>(data[0]));
}

void BleKeyClient::onUnlockRespNotify(uint8_t* data, size_t len) {
  if (len != sizeof(unlockResp_)) return;
  lock();
  memcpy(unlockResp_, data, len);
  unlockRespRcvd_ = true;
  unlock();
  Serial.println("[BLEKEY] unlock response received");
}

void BleKeyClient::update() {
  switch (phase_) {
    case Phase::Scanning: {
      bool found = false;
      lock(); found = found_; unlock();
      if (found) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        phase_ = Phase::Connecting;
        client_ = NimBLEDevice::createClient();
        client_->setClientCallbacks(clientCallbacks_, false);
        if (!client_->connect(NimBLEAddress(foundAddr_, foundType_))) {
          error_ = Error::ConnectFailed;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        Serial.println("[BLEKEY] connected");
        NimBLERemoteService* service = client_->getService(kServiceUUID);
        if (!service) {
          error_ = Error::ServiceNotFound;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        if (mode_ == 1) {
          NimBLERemoteCharacteristic* pubKey = service->getCharacteristic(kPairPubKeyUUID);
          NimBLERemoteCharacteristic* confirm = service->getCharacteristic(kPairConfirmUUID);
          NimBLERemoteCharacteristic* status = service->getCharacteristic(kPairStatusUUID);
          if (!pubKey || !confirm || !status) {
            error_ = Error::SubscribeFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          const std::string pkStr = pubKey->readValue();
          if (pkStr.size() != kPubKeySize) {
            error_ = Error::BadResponse;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          memcpy(pk_, pkStr.data(), kPubKeySize);
          status->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                         uint8_t* p, size_t l, bool) {
            onPairStatusNotify(p, l);
          });
          const uint8_t one = 1;
          if (!confirm->writeValue(&one, 1, false)) {
            error_ = Error::WriteFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          requestStartMs_ = millis();
          phase_ = Phase::PairRequesting;
        } else if (mode_ == 2) {
          NimBLERemoteCharacteristic* setPin = service->getCharacteristic(kSetPinUUID);
          NimBLERemoteCharacteristic* status = service->getCharacteristic(kUnlockStatusUUID);
          if (!setPin || !status) {
            error_ = Error::SubscribeFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          status->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                         uint8_t* p, size_t l, bool) {
            onUnlockStatusNotify(p, l);
          });
          const uint8_t one = 1;
          if (!setPin->writeValue(&one, 1, false)) {
            error_ = Error::WriteFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          requestStartMs_ = millis();
          phase_ = Phase::SetPinRequesting;
        } else {  // mode 3 unlock
          NimBLERemoteCharacteristic* req = service->getCharacteristic(kUnlockReqUUID);
          NimBLERemoteCharacteristic* resp = service->getCharacteristic(kUnlockRespUUID);
          NimBLERemoteCharacteristic* status = service->getCharacteristic(kUnlockStatusUUID);
          if (!req || !resp || !status) {
            error_ = Error::SubscribeFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          resp->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                       uint8_t* p, size_t l, bool) {
            onUnlockRespNotify(p, l);
          });
          status->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                         uint8_t* p, size_t l, bool) {
            onUnlockStatusNotify(p, l);
          });
          if (!req->writeValue(blob_, kUnlockReqSize, false)) {
            error_ = Error::WriteFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          requestStartMs_ = millis();
          phase_ = Phase::UnlockRequesting;
        }
      } else if (millis() - scanStartMs_ > kScanTimeoutMs) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        error_ = Error::ScanTimeout;
        teardown();
        phase_ = Phase::Failed;
      }
      break;
    }

    case Phase::PairRequesting: {
      bool dis = false, rcvd = false;
      uint8_t st = 0;
      lock(); dis = disconnected_; rcvd = pairStatusRcvd_; st = pairStatus_; unlock();
      if (dis) { error_ = Error::Disconnected; teardown(); phase_ = Phase::Failed; break; }
      if (rcvd && st == kPairAuthorized) {
        saveStoredPk(pk_);
        teardown();
        phase_ = Phase::Paired;
        Serial.println("[BLEKEY] paired (pk saved)");
        break;
      }
      if (rcvd && st == kPairDenied) { teardown(); phase_ = Phase::Denied; break; }
      if (millis() - requestStartMs_ > kAuthTimeoutMs) {
        error_ = Error::Timeout; teardown(); phase_ = Phase::Failed;
      }
      break;
    }

    case Phase::SetPinRequesting: {
      bool dis = false, rcvd = false;
      uint8_t st = 0;
      lock(); dis = disconnected_; rcvd = unlockStatusRcvd_; st = unlockStatus_; unlock();
      if (dis) { error_ = Error::Disconnected; teardown(); phase_ = Phase::Failed; break; }
      if (rcvd && st == kUnlockAuthorized) { teardown(); phase_ = Phase::SetPinDone; break; }
      if (rcvd && st == kUnlockDenied) { teardown(); phase_ = Phase::Denied; break; }
      if (millis() - requestStartMs_ > kAuthTimeoutMs) {
        error_ = Error::Timeout; teardown(); phase_ = Phase::Failed;
      }
      break;
    }

    case Phase::UnlockRequesting: {
      bool dis = false, resp = false;
      lock(); dis = disconnected_; resp = unlockRespRcvd_; unlock();
      if (dis) { error_ = Error::Disconnected; teardown(); phase_ = Phase::Failed; break; }
      if (resp) {
        uint8_t Ksess[kKeySize] = {};
        size_t ml = 0;
        const bool ok = deriveEcdhKey(eSess_, pk_, "m5-vault-session-v1", Ksess) &&
            aesGcmDecrypt(Ksess, unlockResp_, sizeof(unlockResp_), master_, &ml) &&
            ml == vault_2fa::kMasterSize;
        wipe(Ksess, sizeof(Ksess));
        teardown();
        if (ok) {
          masterReady_ = true;
          phase_ = Phase::Unlocked;
          Serial.println("[BLEKEY] vault master received");
        } else {
          error_ = Error::BadResponse;
          phase_ = Phase::Failed;
        }
        break;
      }
      {
        bool rcvd = false; uint8_t st = 0;
        lock(); rcvd = unlockStatusRcvd_; st = unlockStatus_; unlock();
        if (rcvd && st == kUnlockWiped) { teardown(); phase_ = Phase::Failed; break; }
        if (rcvd && st == kUnlockDenied) { teardown(); phase_ = Phase::Denied; break; }
      }
      if (millis() - requestStartMs_ > kAuthTimeoutMs) {
        error_ = Error::Timeout; teardown(); phase_ = Phase::Failed;
      }
      break;
    }

    default:
      break;
  }
}

const char* BleKeyClient::statusText() {
  switch (phase_) {
    case Phase::Scanning: return "Buscando M5Core2...";
    case Phase::Connecting: return "Conectando...";
    case Phase::PairRequesting: return "Autoriza el emparejamiento en el Core2...";
    case Phase::Paired: return "EMPAREJADO";
    case Phase::SetPinRequesting: return "Fija el PIN en el Core2...";
    case Phase::SetPinDone: return "PIN FIJADO";
    case Phase::UnlockRequesting: return "Introduce el PIN en el Core2...";
    case Phase::Unlocked: return "VAULT DESBLOQUEADO";
    case Phase::Denied: return "DENEGADO";
    case Phase::Failed: return "La operacion ha fallado";
    case Phase::Cancelled: return "Cancelado";
    default: return "";
  }
}

void BleKeyClient::teardown() {
  if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
  if (client_) {
    if (client_->isConnected()) client_->disconnect();
    NimBLEDevice::deleteClient(client_);
    client_ = nullptr;
  }
  lock();
  found_ = false;
  connected_ = false;
  disconnected_ = false;
  pairStatusRcvd_ = false;
  unlockStatusRcvd_ = false;
  unlockRespRcvd_ = false;
  unlock();
  if (bleOn_) { NimBLEDevice::deinit(true); bleOn_ = false; }
}

}  // namespace ble_key
