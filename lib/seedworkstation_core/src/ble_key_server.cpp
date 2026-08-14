#include "ble_key_server.hpp"

namespace ble_key {

namespace {
constexpr uint32_t kResultHoldMs = 1500;
constexpr size_t kUnlockReqSize = kPubKeySize + vault_2fa::kBlobSize;
constexpr size_t kUnlockRespSize =
    kEciesNonceSize + vault_2fa::kMasterSize + kGcmTagSize;
}

class BleKeyServer::ServerCallbacks : public NimBLEServerCallbacks {
public:
  explicit ServerCallbacks(BleKeyServer* s) : srv(s) {}
  void onConnect(NimBLEServer* p) override { srv->onClientConnect(p); }
  void onDisconnect(NimBLEServer* p) override { srv->onClientDisconnect(p); }
private:
  BleKeyServer* srv;
};

class BleKeyServer::PairCallbacks : public NimBLECharacteristicCallbacks {
public:
  explicit PairCallbacks(BleKeyServer* s) : srv(s) {}
  void onWrite(NimBLECharacteristic* c) override { srv->onPairConfirmWrite(c); }
private:
  BleKeyServer* srv;
};

class BleKeyServer::SetPinCallbacks : public NimBLECharacteristicCallbacks {
public:
  explicit SetPinCallbacks(BleKeyServer* s) : srv(s) {}
  void onWrite(NimBLECharacteristic* c) override { srv->onSetPinWrite(c); }
private:
  BleKeyServer* srv;
};

class BleKeyServer::UnlockCallbacks : public NimBLECharacteristicCallbacks {
public:
  explicit UnlockCallbacks(BleKeyServer* s) : srv(s) {}
  void onWrite(NimBLECharacteristic* c) override { srv->onUnlockWrite(c); }
private:
  BleKeyServer* srv;
};

BleKeyServer::BleKeyServer() {
  mux_ = xSemaphoreCreateMutex();
  serverCallbacks_ = new ServerCallbacks(this);
  pairCallbacks_ = new PairCallbacks(this);
  setPinCallbacks_ = new SetPinCallbacks(this);
  unlockCallbacks_ = new UnlockCallbacks(this);
}

BleKeyServer::~BleKeyServer() {
  delete serverCallbacks_;
  delete pairCallbacks_;
  delete setPinCallbacks_;
  delete unlockCallbacks_;
  if (mux_) vSemaphoreDelete(mux_);
  mux_ = nullptr;
}

bool BleKeyServer::begin() {
  if (vault_2fa::hasEncryptedSk()) {
    if (!loadStoredPk(pub_)) return false;
    Serial.println("[BLEKEY] sk locked (PIN required)");
  } else if (loadStoredPrivKey(sk_)) {
    if (!derivePublicKey(sk_, pub_)) return false;
    saveStoredPk(pub_);
    Serial.println("[BLEKEY] sk loaded (no PIN yet)");
  } else {
    if (!generateKey(sk_)) return false;
    saveStoredPrivKey(sk_);
    if (!derivePublicKey(sk_, pub_)) return false;
    saveStoredPk(pub_);
    Serial.println("[BLEKEY] identity generated");
  }

  NimBLEDevice::init(kDeviceName);
  server_ = NimBLEDevice::createServer();
  if (!server_) return false;
  server_->setCallbacks(serverCallbacks_);
  NimBLEService* svc = server_->createService(kServiceUUID);
  if (!svc) return false;

  pairPubChar_ = svc->createCharacteristic(kPairPubKeyUUID, NIMBLE_PROPERTY::READ);
  pairPubChar_->setValue(pub_, kPubKeySize);
  pairConfirmChar_ = svc->createCharacteristic(kPairConfirmUUID, NIMBLE_PROPERTY::WRITE);
  pairConfirmChar_->setCallbacks(pairCallbacks_);
  pairStatusChar_ = svc->createCharacteristic(kPairStatusUUID,
                                              NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  setPinChar_ = svc->createCharacteristic(kSetPinUUID, NIMBLE_PROPERTY::WRITE);
  setPinChar_->setCallbacks(setPinCallbacks_);
  unlockReqChar_ = svc->createCharacteristic(kUnlockReqUUID, NIMBLE_PROPERTY::WRITE);
  unlockReqChar_->setCallbacks(unlockCallbacks_);
  unlockRespChar_ = svc->createCharacteristic(kUnlockRespUUID,
                                              NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  unlockStatusChar_ = svc->createCharacteristic(kUnlockStatusUUID,
                                                NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  infoChar_ = svc->createCharacteristic(kDeviceInfoUUID, NIMBLE_PROPERTY::READ);
  infoChar_->setValue(kDeviceInfoValue);
  svc->start();

  const uint8_t idle = kPairIdle;
  pairStatusChar_->setValue(&idle, 1);
  unlockStatusChar_->setValue(&idle, 1);

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(kServiceUUID);
  adv->setName(kDeviceName);
  adv->setScanResponse(true);
  adv->start();

  state_ = State::Idle;
  pairState_ = PairState::Idle;
  pinState_ = PinState::Idle;
  Serial.println("[BLEKEY] advertising as M5Core2-Key");
  return true;
}

// ---- emparejamiento (intercambio de pk + confirmacion) ----

void BleKeyServer::onPairConfirmWrite(NimBLECharacteristic*) {
  if (pairState_ != PairState::Idle) return;
  pairState_ = PairState::Requested;
  pairStartMs_ = 0;
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
  pairState_ = PairState::Authorized;
  pairResultStartMs_ = 0;
  hasPaired_ = true;
  if (pairPubChar_) pairPubChar_->setValue(pub_, kPubKeySize);
  notifyPairStatus(kPairAuthorized);
  Serial.println("[BLEKEY] paired");
}

void BleKeyServer::denyPairing() {
  if (pairState_ != PairState::Requested) return;
  pairState_ = PairState::Denied;
  pairResultStartMs_ = 0;
  notifyPairStatus(kPairDenied);
  Serial.println("[BLEKEY] pairing denied");
}

// ---- PIN ----

void BleKeyServer::onSetPinWrite(NimBLECharacteristic*) {
  if (vault_2fa::hasEncryptedSk()) {
    // PIN ya fijado: no hay nada que hacer.
    notifyUnlockStatus(kUnlockAuthorized);
    Serial.println("[BLEKEY] PIN already set");
    return;
  }
  if (!loadStoredPrivKey(sk_)) {
    notifyUnlockStatus(kUnlockDenied);
    return;
  }
  memset(pinBuffer_, 0, sizeof(pinBuffer_));
  memset(pinFirst_, 0, sizeof(pinFirst_));
  pinFails_ = 0;
  pinState_ = PinState::SetEntry;
  notifyUnlockStatus(kUnlockPinRequired);
  Serial.println("[BLEKEY] PIN set requested");
}

void BleKeyServer::pinDigit(char d) {
  if (pinState_ != PinState::SetEntry && pinState_ != PinState::SetConfirm &&
      pinState_ != PinState::UnlockEntry) return;
  const size_t len = strlen(pinBuffer_);
  if (len < 6) { pinBuffer_[len] = d; pinBuffer_[len + 1] = '\0'; }
}

void BleKeyServer::pinBackspace() {
  const size_t len = strlen(pinBuffer_);
  if (len) pinBuffer_[len - 1] = '\0';
}

void BleKeyServer::pinSubmit() {
  if (strlen(pinBuffer_) != 6) return;
  if (pinState_ == PinState::SetEntry) {
    strncpy(pinFirst_, pinBuffer_, sizeof(pinFirst_) - 1);
    memset(pinBuffer_, 0, sizeof(pinBuffer_));
    pinState_ = PinState::SetConfirm;
  } else if (pinState_ == PinState::SetConfirm) {
    if (!strcmp(pinBuffer_, pinFirst_)) {
      doSetPin();
    } else {
      pinFails_++;
      memset(pinFirst_, 0, sizeof(pinFirst_));
      memset(pinBuffer_, 0, sizeof(pinBuffer_));
      pinState_ = PinState::SetEntry;
      notifyUnlockStatus(kUnlockPinFailed);
    }
  } else if (pinState_ == PinState::UnlockEntry) {
    if (unlockSkWithPin()) {
      pinFails_ = 0;
      pinState_ = PinState::Done;
      processUnlock();
    } else {
      pinFails_++;
      memset(pinBuffer_, 0, sizeof(pinBuffer_));
      if (pinFails_ >= 3) wipeSk();
      else notifyUnlockStatus(kUnlockPinFailed);
    }
  }
}

void BleKeyServer::pinCancel() {
  memset(pinBuffer_, 0, sizeof(pinBuffer_));
  memset(pinFirst_, 0, sizeof(pinFirst_));
  pinState_ = PinState::Idle;
  if (state_ == State::Requested) {
    lock();
    wipe(unlockReq_, sizeof(unlockReq_));
    unlockReqReady_ = false;
    unlock();
    state_ = State::Denied;
    resultStartMs_ = 0;
    notifyUnlockStatus(kUnlockDenied);
  }
}

bool BleKeyServer::unlockSkWithPin() {
  return vault_2fa::loadDecryptedSk(pinBuffer_, sk_);
}

void BleKeyServer::doSetPin() {
  if (!vault_2fa::saveEncryptedSk(sk_, pinBuffer_)) {
    pinState_ = PinState::Failed;
    notifyUnlockStatus(kUnlockDenied);
    return;
  }
  ble_key::detail::nvsErase("kpriv");
  memset(pinBuffer_, 0, sizeof(pinBuffer_));
  memset(pinFirst_, 0, sizeof(pinFirst_));
  pinState_ = PinState::Done;
  notifyUnlockStatus(kUnlockAuthorized);
  Serial.println("[BLEKEY] PIN set");
}

void BleKeyServer::wipeSk() {
  vault_2fa::eraseEncryptedSk();
  memset(pinBuffer_, 0, sizeof(pinBuffer_));
  memset(pinFirst_, 0, sizeof(pinFirst_));
  pinFails_ = 0;
  pinState_ = PinState::Idle;
  lock();
  wipe(unlockReq_, sizeof(unlockReq_));
  unlockReqReady_ = false;
  unlock();
  state_ = State::Denied;
  resultStartMs_ = 0;
  notifyUnlockStatus(kUnlockWiped);
  Serial.println("[BLEKEY] PIN failed 3x: sk wiped");
}

// ---- desbloqueo ----

void BleKeyServer::onUnlockWrite(NimBLECharacteristic* c) {
  const std::string v = c->getValue();
  if (v.size() != kUnlockReqSize) {
    notifyUnlockStatus(kUnlockDenied);
    return;
  }
  if (!vault_2fa::hasEncryptedSk()) {
    notifyUnlockStatus(kUnlockDenied);
    Serial.println("[BLEKEY] unlock denied: no PIN set");
    return;
  }
  lock();
  memcpy(unlockReq_, v.data(), kUnlockReqSize);
  unlockReqReady_ = true;
  state_ = State::Requested;
  requestStartMs_ = 0;
  unlock();
  memset(pinBuffer_, 0, sizeof(pinBuffer_));
  pinFails_ = 0;
  pinState_ = PinState::UnlockEntry;
  notifyUnlockStatus(kUnlockPinRequired);
  Serial.println("[BLEKEY] unlock requested");
}

void BleKeyServer::notifyUnlockStatus(uint8_t s) {
  if (!unlockStatusChar_) return;
  unlockStatusChar_->setValue(&s, 1);
  unlockStatusChar_->notify();
}

void BleKeyServer::processUnlock() {
  // unlockReq_ = E_sess(65) || ECIES(M)(125)
  uint8_t M[vault_2fa::kMasterSize] = {};
  size_t Mlen = 0;
  const bool ok = eciesDecrypt(sk_, unlockReq_ + kPubKeySize,
                               vault_2fa::kBlobSize, M, &Mlen);
  if (ok && Mlen == vault_2fa::kMasterSize) {
    uint8_t Ksess[kKeySize] = {};
    if (deriveEcdhKey(sk_, unlockReq_, "m5-vault-session-v1", Ksess)) {
      uint8_t resp[kUnlockRespSize] = {};
      size_t respLen = 0;
      if (aesGcmEncrypt(Ksess, M, vault_2fa::kMasterSize, resp, &respLen) &&
          unlockRespChar_) {
        unlockRespChar_->setValue(resp, respLen);
        unlockRespChar_->notify();
      }
      wipe(resp, sizeof(resp));
    }
    wipe(Ksess, sizeof(Ksess));
  }
  wipe(M, sizeof(M));
  wipe(sk_, sizeof(sk_));  // la privada no debe quedar en RAM
  lock();
  wipe(unlockReq_, sizeof(unlockReq_));
  unlockReqReady_ = false;
  unlock();
  state_ = State::Authorized;
  resultStartMs_ = 0;
  notifyUnlockStatus(kUnlockAuthorized);
  Serial.println("[BLEKEY] vault master decrypted");
}

// ---- conexion / estados ----

void BleKeyServer::onClientConnect(NimBLEServer*) {
  Serial.println("[BLEKEY] client connected");
}

void BleKeyServer::onClientDisconnect(NimBLEServer*) {
  Serial.println("[BLEKEY] client disconnected");
  lock();
  if (state_ == State::Requested) {
    wipe(unlockReq_, sizeof(unlockReq_));
    unlockReqReady_ = false;
    state_ = State::Idle;
  }
  if (pairState_ == PairState::Requested) pairState_ = PairState::Idle;
  unlock();
  pinState_ = PinState::Idle;
  memset(pinBuffer_, 0, sizeof(pinBuffer_));
  memset(pinFirst_, 0, sizeof(pinFirst_));
}

void BleKeyServer::update() {
  const uint32_t now = millis();
  if (state_ == State::Requested) {
    if (requestStartMs_ == 0) requestStartMs_ = now;
    else if (now - requestStartMs_ > kAuthTimeoutMs) {
      lock();
      wipe(unlockReq_, sizeof(unlockReq_));
      unlockReqReady_ = false;
      unlock();
      state_ = State::Timeout;
      pinState_ = PinState::Idle;
      memset(pinBuffer_, 0, sizeof(pinBuffer_));
      resultStartMs_ = 0;
      notifyUnlockStatus(kUnlockDenied);
      Serial.println("[BLEKEY] unlock timeout");
    }
  } else if (state_ == State::Authorized || state_ == State::Denied ||
             state_ == State::Timeout) {
    if (resultStartMs_ == 0) resultStartMs_ = now;
    else if (now - resultStartMs_ > kResultHoldMs) { state_ = State::Idle; resultStartMs_ = 0; }
  }

  if (pairState_ == PairState::Requested) {
    if (pairStartMs_ == 0) pairStartMs_ = now;
    else if (now - pairStartMs_ > kAuthTimeoutMs) {
      pairState_ = PairState::Timeout;
      pairResultStartMs_ = 0;
      notifyPairStatus(kPairDenied);
    }
  } else if (pairState_ == PairState::Authorized || pairState_ == PairState::Denied ||
             pairState_ == PairState::Timeout) {
    if (pairResultStartMs_ == 0) pairResultStartMs_ = now;
    else if (now - pairResultStartMs_ > kResultHoldMs) {
      pairState_ = PairState::Idle;
      pairResultStartMs_ = 0;
      notifyPairStatus(kPairIdle);
    }
  }
}

}  // namespace ble_key
