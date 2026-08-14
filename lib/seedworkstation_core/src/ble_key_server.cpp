#include "ble_key_server.hpp"

namespace ble_key {

namespace {
constexpr uint32_t kResultHoldMs = 1500;
}

class BleKeyServer::ServerCallbacks : public NimBLEServerCallbacks {
public:
  explicit ServerCallbacks(BleKeyServer* s) : srv(s) {}
  void onConnect(NimBLEServer* p) override { srv->onClientConnect(p); }
  void onDisconnect(NimBLEServer* p) override { srv->onClientDisconnect(p); }
private:
  BleKeyServer* srv;
};

class BleKeyServer::ChallengeCallbacks : public NimBLECharacteristicCallbacks {
public:
  explicit ChallengeCallbacks(BleKeyServer* s) : srv(s) {}
  void onWrite(NimBLECharacteristic* c) override { srv->onChallengeWrite(c); }
private:
  BleKeyServer* srv;
};

class BleKeyServer::PairCallbacks : public NimBLECharacteristicCallbacks {
public:
  explicit PairCallbacks(BleKeyServer* s) : srv(s) {}
  void onWrite(NimBLECharacteristic* c) override { srv->onPairPubWrite(c); }
private:
  BleKeyServer* srv;
};

BleKeyServer::BleKeyServer() {
  mux_ = xSemaphoreCreateMutex();
  serverCallbacks_ = new ServerCallbacks(this);
  challengeCallbacks_ = new ChallengeCallbacks(this);
  pairCallbacks_ = new PairCallbacks(this);
}

BleKeyServer::~BleKeyServer() {
  delete serverCallbacks_;
  delete challengeCallbacks_;
  delete pairCallbacks_;
  if (mux_) vSemaphoreDelete(mux_);
  mux_ = nullptr;
}

bool BleKeyServer::begin() {
  if (!loadStoredPrivKey(priv_)) {
    if (!generateKey(priv_)) return false;
    saveStoredPrivKey(priv_);
    Serial.println("[BLEKEY] identity key generated");
  }
  if (!derivePublicKey(priv_, pub_)) return false;
  hasPaired_ = loadStoredKey(kpair_);

  NimBLEDevice::init(kDeviceName);
  server_ = NimBLEDevice::createServer();
  if (!server_) return false;
  server_->setCallbacks(serverCallbacks_);
  NimBLEService* svc = server_->createService(kServiceUUID);
  if (!svc) return false;

  challengeChar_ = svc->createCharacteristic(kChallengeUUID, NIMBLE_PROPERTY::WRITE);
  challengeChar_->setCallbacks(challengeCallbacks_);
  responseChar_ = svc->createCharacteristic(kResponseUUID,
                                            NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  statusChar_ = svc->createCharacteristic(kStatusUUID,
                                          NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);

  pairPubChar_ = svc->createCharacteristic(kPairPubKeyUUID, NIMBLE_PROPERTY::WRITE);
  pairPubChar_->setCallbacks(pairCallbacks_);
  pairResponseChar_ = svc->createCharacteristic(kPairResponseUUID,
                                                NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  pairStatusChar_ = svc->createCharacteristic(kPairStatusUUID,
                                              NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);

  infoChar_ = svc->createCharacteristic(kDeviceInfoUUID, NIMBLE_PROPERTY::READ);
  infoChar_->setValue(kDeviceInfoValue);
  svc->start();

  const uint8_t idle = kStatusIdle;
  statusChar_->setValue(&idle, 1);
  pairStatusChar_->setValue(&idle, 1);

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(kServiceUUID);
  adv->setName(kDeviceName);
  adv->setScanResponse(true);
  adv->start();

  state_ = State::Idle;
  pairState_ = PairState::Idle;
  Serial.println("[BLEKEY] advertising as M5Core2-Key");
  return true;
}

// ---- desbloqueo (challenge/response) ----

void BleKeyServer::onChallengeWrite(NimBLECharacteristic* c) {
  if (!hasPaired_) {
    Serial.println("[BLEKEY] challenge ignored: not paired");
    return;
  }
  const std::string v = c->getValue();
  if (v.size() != kChallengeSize) {
    Serial.println("[BLEKEY] challenge malformed");
    return;
  }
  lock();
  memcpy(challenge_, v.data(), kChallengeSize);
  challengeReady_ = true;
  state_ = State::Requested;
  requestStartMs_ = 0;
  unlock();
  notifyStatus(kStatusRequested);
  Serial.println("[BLEKEY] challenge received");
}

void BleKeyServer::notifyStatus(Status s) {
  if (!statusChar_) return;
  const uint8_t b = static_cast<uint8_t>(s);
  statusChar_->setValue(&b, 1);
  statusChar_->notify();
}

void BleKeyServer::allow() {
  if (state_ != State::Requested || !hasPaired_) return;
  uint8_t resp[kResponseSize] = {};
  lock();
  const bool ok = hmacSha256(kpair_, kKeySize, challenge_, kChallengeSize, resp);
  wipe(challenge_, sizeof(challenge_));
  challengeReady_ = false;
  state_ = State::Authorized;
  unlock();
  resultStartMs_ = 0;
  if (ok && responseChar_) {
    responseChar_->setValue(resp, kResponseSize);
    responseChar_->notify();
  }
  notifyStatus(kStatusAuthorized);
  wipe(resp, sizeof(resp));
  Serial.println("[BLEKEY] authorization confirmed");
}

void BleKeyServer::deny() {
  if (state_ != State::Requested) return;
  lock();
  wipe(challenge_, sizeof(challenge_));
  challengeReady_ = false;
  state_ = State::Denied;
  unlock();
  resultStartMs_ = 0;
  notifyStatus(kStatusDenied);
  Serial.println("[BLEKEY] denied");
}

// ---- emparejamiento ----

void BleKeyServer::onPairPubWrite(NimBLECharacteristic* c) {
  const std::string v = c->getValue();
  if (v.size() != kPubKeySize) {
    Serial.println("[BLEKEY] pair pubkey malformed");
    return;
  }
  lock();
  memcpy(pairPub_, v.data(), kPubKeySize);
  pairPubReady_ = true;
  pairState_ = PairState::Requested;
  pairStartMs_ = 0;
  unlock();
  notifyPairStatus(kPairRequested);
  Serial.println("[BLEKEY] pairing requested");
}

void BleKeyServer::notifyPairStatus(PairStatus s) {
  if (!pairStatusChar_) return;
  const uint8_t b = static_cast<uint8_t>(s);
  pairStatusChar_->setValue(&b, 1);
  pairStatusChar_->notify();
}

void BleKeyServer::allowPairing() {
  if (pairState_ != PairState::Requested) return;
  lock();
  wipe(kpair_, sizeof(kpair_));
  const bool ok = deriveSharedKpair(priv_, pairPub_, kpair_);
  wipe(pairPub_, sizeof(pairPub_));
  pairPubReady_ = false;
  pairState_ = PairState::Authorized;
  unlock();
  pairResultStartMs_ = 0;
  if (ok) {
    saveStoredKey(kpair_);
    hasPaired_ = true;
    if (pairResponseChar_) {
      pairResponseChar_->setValue(pub_, kPubKeySize);
      pairResponseChar_->notify();
    }
    Serial.println("[BLEKEY] paired");
  } else {
    Serial.println("[BLEKEY] pairing derivation failed");
  }
  notifyPairStatus(ok ? kPairAuthorized : kPairDenied);
}

void BleKeyServer::denyPairing() {
  if (pairState_ != PairState::Requested) return;
  lock();
  wipe(pairPub_, sizeof(pairPub_));
  pairPubReady_ = false;
  pairState_ = PairState::Denied;
  unlock();
  pairResultStartMs_ = 0;
  notifyPairStatus(kPairDenied);
  Serial.println("[BLEKEY] pairing denied");
}

// ---- conexion / estados ----

void BleKeyServer::onClientConnect(NimBLEServer*) {
  Serial.println("[BLEKEY] client connected");
}

void BleKeyServer::onClientDisconnect(NimBLEServer*) {
  Serial.println("[BLEKEY] client disconnected");
  lock();
  if (state_ == State::Requested) {
    wipe(challenge_, sizeof(challenge_));
    challengeReady_ = false;
    state_ = State::Idle;
  }
  if (pairState_ == PairState::Requested) {
    wipe(pairPub_, sizeof(pairPub_));
    pairPubReady_ = false;
    pairState_ = PairState::Idle;
  }
  unlock();
}

void BleKeyServer::update() {
  if (state_ == State::Requested) {
    if (requestStartMs_ == 0) {
      requestStartMs_ = millis();
    } else if (millis() - requestStartMs_ > kAuthTimeoutMs) {
      Serial.println("[BLEKEY] auth timeout");
      lock();
      wipe(challenge_, sizeof(challenge_));
      challengeReady_ = false;
      state_ = State::Timeout;
      unlock();
      resultStartMs_ = 0;
      notifyStatus(kStatusTimeout);
    }
  } else if (state_ == State::Authorized || state_ == State::Denied ||
             state_ == State::Timeout) {
    if (resultStartMs_ == 0) {
      resultStartMs_ = millis();
    } else if (millis() - resultStartMs_ > kResultHoldMs) {
      state_ = State::Idle;
      resultStartMs_ = 0;
      notifyStatus(kStatusIdle);
    }
  }

  if (pairState_ == PairState::Requested) {
    if (pairStartMs_ == 0) {
      pairStartMs_ = millis();
    } else if (millis() - pairStartMs_ > kAuthTimeoutMs) {
      Serial.println("[BLEKEY] pairing timeout");
      lock();
      wipe(pairPub_, sizeof(pairPub_));
      pairPubReady_ = false;
      pairState_ = PairState::Timeout;
      unlock();
      pairResultStartMs_ = 0;
      notifyPairStatus(kPairDenied);
    }
  } else if (pairState_ == PairState::Authorized || pairState_ == PairState::Denied ||
             pairState_ == PairState::Timeout) {
    if (pairResultStartMs_ == 0) {
      pairResultStartMs_ = millis();
    } else if (millis() - pairResultStartMs_ > kResultHoldMs) {
      pairState_ = PairState::Idle;
      pairResultStartMs_ = 0;
      notifyPairStatus(kPairIdle);
    }
  }
}

}  // namespace ble_key
