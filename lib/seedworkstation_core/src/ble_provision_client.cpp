#include "ble_provision_client.hpp"

namespace ble_provision {

namespace {
constexpr uint32_t kScanTimeoutMs = 15000;
}

class BleProvisionClient::ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
public:
  explicit ScanCallbacks(BleProvisionClient* c) : client(c) {}
  void onResult(NimBLEAdvertisedDevice* d) override { client->onScanResult(d); }
private:
  BleProvisionClient* client;
};

class BleProvisionClient::ClientCallbacks : public NimBLEClientCallbacks {
public:
  explicit ClientCallbacks(BleProvisionClient* c) : client(c) {}
  void onConnect(NimBLEClient* c) override { client->onConnectCallback(c); }
  void onDisconnect(NimBLEClient* c) override { client->onDisconnectCallback(c); }
private:
  BleProvisionClient* client;
};

BleProvisionClient::BleProvisionClient() {
  mux_ = xSemaphoreCreateMutex();
  scanCallbacks_ = new ScanCallbacks(this);
  clientCallbacks_ = new ClientCallbacks(this);
}

BleProvisionClient::~BleProvisionClient() {
  teardown();
  delete scanCallbacks_;
  delete clientCallbacks_;
  if (mux_) vSemaphoreDelete(mux_);
  mux_ = nullptr;
}

void BleProvisionClient::start(const uint16_t* words, uint8_t count,
                               const uint8_t fingerprint[4]) {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting) return;
  teardown();
  ble_key::wipe(payload_, sizeof(payload_));
  payloadLen_ = buildPayload(words, count, fingerprint, payload_);
  if (!payloadLen_) {
    phase_ = Phase::Failed;
    error_ = Error::BadResponse;
    return;
  }
  lock();
  found_ = connected_ = disconnected_ = false;
  statusRcvd_ = false;
  status_ = 0;
  unlock();
  error_ = Error::None;
  beginScan();
}

void BleProvisionClient::beginScan() {
  Serial.println("[PROVIS] scanning");
  NimBLEDevice::init("M5Paper-Provis");
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

void BleProvisionClient::cancel() {
  if (phase_ == Phase::Idle || phase_ == Phase::Cancelled) return;
  teardown();
  phase_ = Phase::Cancelled;
}

void BleProvisionClient::clear() {
  teardown();
  ble_key::wipe(payload_, sizeof(payload_));
  payloadLen_ = 0;
  ble_key::wipe(pk_, sizeof(pk_));
  error_ = Error::None;
  phase_ = Phase::Idle;
}

void BleProvisionClient::onScanResult(NimBLEAdvertisedDevice* device) {
  if (found_) return;
  if (device->haveName() && device->getName() == kDeviceName) {
    lock();
    found_ = true;
    foundAddr_ = device->getAddress().toString();
    foundType_ = device->getAddress().getType();
    unlock();
    Serial.println("[PROVIS] M5Stick found");
  }
}

void BleProvisionClient::onConnectCallback(NimBLEClient*) {
  lock(); connected_ = true; disconnected_ = false; unlock();
}

void BleProvisionClient::onDisconnectCallback(NimBLEClient*) {
  lock(); disconnected_ = true; connected_ = false; unlock();
  Serial.println("[PROVIS] disconnected");
}

void BleProvisionClient::onStatusNotify(uint8_t* data, size_t len) {
  if (len < 1) return;
  lock(); status_ = data[0]; statusRcvd_ = true; unlock();
  Serial.printf("[PROVIS] status=%u\n", static_cast<unsigned>(data[0]));
}

void BleProvisionClient::update() {
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
        Serial.println("[PROVIS] connected");
        NimBLERemoteService* service = client_->getService(kServiceUUID);
        if (!service) {
          error_ = Error::ServiceNotFound;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        NimBLERemoteCharacteristic* pubKey = service->getCharacteristic(kPubKeyUUID);
        NimBLERemoteCharacteristic* req = service->getCharacteristic(kReqUUID);
        NimBLERemoteCharacteristic* status = service->getCharacteristic(kStatusUUID);
        if (!pubKey || !req || !status) {
          error_ = Error::SubscribeFailed;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        const std::string pkStr = pubKey->readValue();
        if (pkStr.size() != ble_key::kPubKeySize) {
          error_ = Error::BadResponse;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        memcpy(pk_, pkStr.data(), ble_key::kPubKeySize);
        status->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                       uint8_t* p, size_t l, bool) {
          onStatusNotify(p, l);
        });
        uint8_t blob[kBlobSize] = {};
        size_t blobLen = 0;
        const bool ok = encrypt(pk_, payload_, payloadLen_, blob, &blobLen);
        ble_key::wipe(pk_, sizeof(pk_));
        if (!ok) {
          error_ = Error::BleInit;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        if (!req->writeValue(blob, blobLen, false)) {
          ble_key::wipe(blob, sizeof(blob));
          error_ = Error::WriteFailed;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        ble_key::wipe(blob, sizeof(blob));
        requestStartMs_ = millis();
        phase_ = Phase::AwaitingConfirm;
        Serial.println("[PROVIS] seed sent, awaiting confirmation");
      } else if (millis() - scanStartMs_ > kScanTimeoutMs) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        error_ = Error::ScanTimeout;
        teardown();
        phase_ = Phase::Failed;
      }
      break;
    }

    case Phase::AwaitingConfirm: {
      bool dis = false, rcvd = false;
      uint8_t st = 0;
      lock(); dis = disconnected_; rcvd = statusRcvd_; st = status_; unlock();
      if (dis) { error_ = Error::Disconnected; teardown(); phase_ = Phase::Failed; break; }
      if (rcvd && st == kAccepted) {
        teardown();
        phase_ = Phase::Provisioned;
        Serial.println("[PROVIS] provisioned");
        break;
      }
      if (rcvd && st == kDenied) { teardown(); phase_ = Phase::Denied; break; }
      if (rcvd && st == kError) {
        error_ = Error::BadResponse;
        teardown();
        phase_ = Phase::Failed;
        break;
      }
      if (millis() - requestStartMs_ > kTimeoutMs) {
        error_ = Error::Timeout;
        teardown();
        phase_ = Phase::Failed;
      }
      break;
    }

    default:
      break;
  }
}

const char* BleProvisionClient::statusText() {
  switch (phase_) {
    case Phase::Scanning: return "Buscando M5Stick...";
    case Phase::Connecting: return "Conectando...";
    case Phase::AwaitingConfirm: return "Confirma en el M5Stick...";
    case Phase::Provisioned: return "PROVISIONADO";
    case Phase::Denied: return "RECHAZADO";
    case Phase::Failed: return "La operacion ha fallado";
    case Phase::Cancelled: return "Cancelado";
    default: return "";
  }
}

void BleProvisionClient::teardown() {
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
  statusRcvd_ = false;
  unlock();
  if (bleOn_) { NimBLEDevice::deinit(true); bleOn_ = false; }
}

}  // namespace ble_provision
