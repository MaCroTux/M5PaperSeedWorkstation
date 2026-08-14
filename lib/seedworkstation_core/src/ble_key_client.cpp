#include "ble_key_client.hpp"

namespace ble_key {

namespace {
constexpr uint32_t kScanTimeoutMs = 15000;

bool ctEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; ++i) d |= a[i] ^ b[i];
  return d == 0;
}
}  // namespace

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

void BleKeyClient::start() {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting ||
      phase_ == Phase::Requesting) return;
  teardown();
  pairingMode_ = false;
  if (!loadStoredKey(key_)) {
    Serial.println("[BLEKEY] no stored key");
    phase_ = Phase::Failed;
    error_ = Error::None;
    return;
  }
  esp_fill_random(challenge_, kChallengeSize);
  lock();
  found_ = false;
  connected_ = false;
  disconnected_ = false;
  responseReceived_ = false;
  memset(response_, 0, sizeof(response_));
  statusReceived_ = false;
  status_ = kStatusIdle;
  unlock();
  error_ = Error::None;
  beginScan();
}

void BleKeyClient::startPairing() {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting ||
      phase_ == Phase::Requesting) return;
  teardown();
  pairingMode_ = true;
  if (!generateKeyPair(ephPriv_, ephPub_)) {
    phase_ = Phase::Failed;
    error_ = Error::BleInit;
    return;
  }
  lock();
  found_ = false;
  connected_ = false;
  disconnected_ = false;
  responseReceived_ = false;
  statusReceived_ = false;
  pairResponseReceived_ = false;
  pairStatusReceived_ = false;
  pairStatus_ = kPairIdle;
  unlock();
  error_ = Error::None;
  beginScan();
}

void BleKeyClient::beginScan() {
  Serial.println("[BLEKEY] stack=NimBLE");
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
  Serial.println("[BLEKEY] cancel");
  teardown();
  phase_ = Phase::Cancelled;
}

void BleKeyClient::clear() {
  teardown();
  wipe(key_, sizeof(key_));
  wipe(challenge_, sizeof(challenge_));
  wipe(response_, sizeof(response_));
  wipe(ephPriv_, sizeof(ephPriv_));
  wipe(ephPub_, sizeof(ephPub_));
  wipe(theirPub_, sizeof(theirPub_));
  error_ = Error::None;
  phase_ = Phase::Idle;
  pairingMode_ = false;
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
  lock();
  connected_ = true;
  disconnected_ = false;
  unlock();
}

void BleKeyClient::onDisconnectCallback(NimBLEClient*) {
  lock();
  disconnected_ = true;
  connected_ = false;
  unlock();
  Serial.println("[BLEKEY] disconnected");
}

void BleKeyClient::onResponseNotify(uint8_t* data, size_t len) {
  if (len != kResponseSize) return;
  lock();
  memcpy(response_, data, kResponseSize);
  responseReceived_ = true;
  unlock();
  Serial.println("[BLEKEY] response received");
}

void BleKeyClient::onStatusNotify(uint8_t* data, size_t len) {
  if (len < 1) return;
  lock();
  status_ = static_cast<Status>(data[0]);
  statusReceived_ = true;
  unlock();
  Serial.printf("[BLEKEY] status=%u\n", static_cast<unsigned>(data[0]));
}

void BleKeyClient::onPairResponseNotify(uint8_t* data, size_t len) {
  if (len != kPubKeySize) return;
  lock();
  memcpy(theirPub_, data, kPubKeySize);
  pairResponseReceived_ = true;
  unlock();
  Serial.println("[BLEKEY] pair pubkey received");
}

void BleKeyClient::onPairStatusNotify(uint8_t* data, size_t len) {
  if (len < 1) return;
  lock();
  pairStatus_ = static_cast<PairStatus>(data[0]);
  pairStatusReceived_ = true;
  unlock();
  Serial.printf("[BLEKEY] pair status=%u\n", static_cast<unsigned>(data[0]));
}

void BleKeyClient::update() {
  switch (phase_) {
    case Phase::Scanning: {
      bool found = false;
      lock();
      found = found_;
      unlock();
      if (found) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }

        phase_ = Phase::Connecting;
        client_ = NimBLEDevice::createClient();
        client_->setClientCallbacks(clientCallbacks_, false);
        if (!client_->connect(NimBLEAddress(foundAddr_, foundType_))) {
          Serial.println("[BLEKEY] connect failed");
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

        if (pairingMode_) {
          NimBLERemoteCharacteristic* pubKey =
              service->getCharacteristic(kPairPubKeyUUID);
          NimBLERemoteCharacteristic* response =
              service->getCharacteristic(kPairResponseUUID);
          NimBLERemoteCharacteristic* status =
              service->getCharacteristic(kPairStatusUUID);
          if (!pubKey || !response || !status) {
            error_ = Error::SubscribeFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          response->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                           uint8_t* p, size_t l, bool) {
            onPairResponseNotify(p, l);
          });
          status->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                         uint8_t* p, size_t l, bool) {
            onPairStatusNotify(p, l);
          });
          if (!pubKey->writeValue(ephPub_, kPubKeySize, false)) {
            error_ = Error::WriteFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          Serial.println("[BLEKEY] pair pubkey sent");
          requestStartMs_ = millis();
          phase_ = Phase::Requesting;
        } else {
          NimBLERemoteCharacteristic* challenge =
              service->getCharacteristic(kChallengeUUID);
          NimBLERemoteCharacteristic* response =
              service->getCharacteristic(kResponseUUID);
          NimBLERemoteCharacteristic* status =
              service->getCharacteristic(kStatusUUID);
          if (!challenge || !response || !status) {
            error_ = Error::SubscribeFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          response->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                           uint8_t* p, size_t l, bool) {
            onResponseNotify(p, l);
          });
          status->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                         uint8_t* p, size_t l, bool) {
            onStatusNotify(p, l);
          });
          if (!challenge->writeValue(challenge_, kChallengeSize, false)) {
            error_ = Error::WriteFailed;
            teardown();
            phase_ = Phase::Failed;
            break;
          }
          Serial.println("[BLEKEY] challenge generated");
          requestStartMs_ = millis();
          phase_ = Phase::Requesting;
        }
      } else if (millis() - scanStartMs_ > kScanTimeoutMs) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        error_ = Error::ScanTimeout;
        Serial.println("[BLEKEY] scan timeout");
        teardown();
        phase_ = Phase::Failed;
      }
      break;
    }

    case Phase::Requesting: {
      bool disconnected = false;
      lock();
      disconnected = disconnected_;
      unlock();
      if (disconnected) {
        error_ = Error::Disconnected;
        teardown();
        phase_ = Phase::Failed;
        break;
      }

      if (pairingMode_) {
        bool response = false, statusRcvd = false;
        PairStatus st = kPairIdle;
        lock();
        response = pairResponseReceived_;
        statusRcvd = pairStatusReceived_;
        st = pairStatus_;
        unlock();
        if (statusRcvd && st == kPairDenied) {
          Serial.println("[BLEKEY] pairing denied");
          teardown();
          phase_ = Phase::Denied;
          break;
        }
        if (response) {
          uint8_t kpair[kKeySize] = {};
          const bool ok = deriveSharedKpair(ephPriv_, theirPub_, kpair);
          if (ok) saveStoredKey(kpair);
          wipe(kpair, sizeof(kpair));
          teardown();
          if (ok) {
            Serial.println("[BLEKEY] paired");
            phase_ = Phase::Paired;
          } else {
            Serial.println("[BLEKEY] pairing derivation failed");
            error_ = Error::BadResponse;
            phase_ = Phase::Failed;
          }
          break;
        }
        if (millis() - requestStartMs_ > kAuthTimeoutMs) {
          error_ = Error::Timeout;
          Serial.println("[BLEKEY] pairing timeout");
          teardown();
          phase_ = Phase::Failed;
        }
      } else {
        bool response = false, statusRcvd = false;
        Status st = kStatusIdle;
        lock();
        response = responseReceived_;
        statusRcvd = statusReceived_;
        st = status_;
        unlock();
        if (statusRcvd && st == kStatusDenied) {
          Serial.println("[BLEKEY] denied by user");
          teardown();
          phase_ = Phase::Denied;
          break;
        }
        if (statusRcvd && st == kStatusTimeout) {
          error_ = Error::Timeout;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        if (response) {
          uint8_t expected[kResponseSize] = {};
          const bool ok = hmacSha256(key_, kKeySize, challenge_, kChallengeSize,
                                     expected);
          const bool match = ok && ctEqual(expected, response_, kResponseSize);
          wipe(expected, sizeof(expected));
          teardown();
          if (match) {
            Serial.println("[BLEKEY] HMAC verified");
            Serial.println("[AUTH] Core2 verified");
            phase_ = Phase::Verified;
          } else {
            Serial.println("[BLEKEY] HMAC mismatch");
            error_ = Error::BadResponse;
            phase_ = Phase::Failed;
          }
          break;
        }
        if (millis() - requestStartMs_ > kAuthTimeoutMs) {
          error_ = Error::Timeout;
          Serial.println("[BLEKEY] auth timeout");
          teardown();
          phase_ = Phase::Failed;
        }
      }
      break;
    }

    default:
      break;
  }
}

const char* BleKeyClient::statusText() {
  if (pairingMode_) {
    switch (phase_) {
      case Phase::Scanning: return "Buscando M5Core2...";
      case Phase::Connecting: return "Conectando...";
      case Phase::Requesting: return "Autoriza el emparejamiento en el Core2...";
      case Phase::Paired: return "EMPAREJADO";
      case Phase::Denied: return "EMPAREJAMIENTO DENEGADO";
      case Phase::Failed: return "El emparejamiento ha fallado";
      case Phase::Cancelled: return "Cancelado";
      default: return "";
    }
  }
  switch (phase_) {
    case Phase::Scanning: return "Buscando M5Core2...";
    case Phase::Connecting: return "Conectando...";
    case Phase::Requesting: return "Esperando autorizacion en el Core2...";
    case Phase::Verified: return "LLAVE VERIFICADA";
    case Phase::Denied: return "AUTORIZACION DENEGADA";
    case Phase::Failed: return "La autenticacion ha fallado";
    case Phase::Cancelled: return "Cancelado";
    default: return "";
  }
}

void BleKeyClient::teardown() {
  if (scan_ && scanning_) {
    scan_->stop();
    scanning_ = false;
  }
  if (client_) {
    if (client_->isConnected()) client_->disconnect();
    NimBLEDevice::deleteClient(client_);
    client_ = nullptr;
  }
  lock();
  found_ = false;
  connected_ = false;
  disconnected_ = false;
  responseReceived_ = false;
  statusReceived_ = false;
  pairResponseReceived_ = false;
  pairStatusReceived_ = false;
  unlock();
  if (bleOn_) {
    NimBLEDevice::deinit(true);
    bleOn_ = false;
  }
}

}  // namespace ble_key
