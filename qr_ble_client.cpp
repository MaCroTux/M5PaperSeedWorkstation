#include "qr_ble_client.hpp"
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace qr_ble {

namespace {
constexpr uint32_t kScanTimeoutMs = 15000;
constexpr uint32_t kWaitTimeoutMs = 60000;
constexpr uint32_t kTransferTimeoutMs = 60000;

bool parseMetadata(const String& raw, QRMetadata& out) {
  out.format = "";
  out.type = "";
  out.size = 0;
  out.sha256 = "";
  out.complete = false;
  int start = 0;
  while (start <= static_cast<int>(raw.length())) {
    const int sep = raw.indexOf(';', start);
    const String pair = sep < 0 ? raw.substring(start) : raw.substring(start, sep);
    const int eq = pair.indexOf('=');
    if (eq > 0) {
      String key = pair.substring(0, eq);
      String val = pair.substring(eq + 1);
      key.trim();
      val.trim();
      if (key.equalsIgnoreCase("FORMAT")) out.format = val;
      else if (key.equalsIgnoreCase("TYPE")) out.type = val;
      else if (key.equalsIgnoreCase("SIZE")) out.size = static_cast<size_t>(strtoul(val.c_str(), nullptr, 10));
      else if (key.equalsIgnoreCase("SHA256")) out.sha256 = val;
    }
    if (sep < 0) break;
    start = sep + 1;
  }
  out.complete = out.format.length() > 0 && out.type.length() > 0 &&
                 out.size > 0 && out.sha256.length() == 64;
  return out.complete;
}

String hexSha256(const uint8_t* data, size_t len) {
  uint8_t digest[32] = {};
  if (mbedtls_sha256_ret(data, len, digest, 0) != 0) return String();
  static const char hex[] = "0123456789abcdef";
  String out;
  out.reserve(64);
  for (uint8_t b : digest) {
    out += hex[b >> 4];
    out += hex[b & 0xF];
  }
  return out;
}
}  // namespace

QRBLEClient::QRBLEClient() {
  mux_ = xSemaphoreCreateMutex();
  scanCallbacks_ = new ScanCallbacks(this);
  clientCallbacks_ = new ClientCallbacks(this);
}

QRBLEClient::~QRBLEClient() {
  teardown();
  delete scanCallbacks_;
  delete clientCallbacks_;
  if (mux_) vSemaphoreDelete(mux_);
  mux_ = nullptr;
}

void QRBLEClient::start() {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting ||
      phase_ == Phase::Waiting || phase_ == Phase::Receiving) return;

  teardown();
  lock();
  statusText_ = "";
  statusChanged_ = false;
  metadataRaw_ = "";
  metadataChanged_ = false;
  chunks_.clear();
  chunksTotal_ = 0;
  chunksBytes_ = 0;
  transferComplete_ = false;
  payloadTooLarge_ = false;
  connected_ = false;
  disconnected_ = false;
  found_ = false;
  foundAddr_.clear();
  unlock();
  metadata_ = QRMetadata{};
  metadataReady_ = false;
  payload_ = QRPayload{};
  payloadReady_ = false;
  error_ = Error::None;

  Serial.println("[BLE] scanning");
  BLEDevice::init(std::string("M5Paper-QR"));
  bleOn_ = true;
  scan_ = BLEDevice::getScan();
  scan_->setActiveScan(true);
  scan_->setInterval(100);
  scan_->setWindow(99);
  scan_->setAdvertisedDeviceCallbacks(scanCallbacks_, false, true);
  scanning_ = scan_->start(0, nullptr, false);
  scanStartMs_ = millis();
  phase_ = Phase::Scanning;
}

void QRBLEClient::cancel() {
  if (phase_ == Phase::Idle || phase_ == Phase::Cancelled) return;
  Serial.println("[BLE] cancel");
  teardown();
  phase_ = Phase::Cancelled;
}

void QRBLEClient::clear() {
  teardown();
  payload_ = QRPayload{};
  payloadReady_ = false;
  metadata_ = QRMetadata{};
  metadataReady_ = false;
  error_ = Error::None;
  phase_ = Phase::Idle;
}

QRPayload QRBLEClient::takePayload() {
  payloadReady_ = false;
  return std::move(payload_);
}

String QRBLEClient::statusText() {
  lock();
  String s = statusText_;
  unlock();
  return s;
}

uint16_t QRBLEClient::receivedChunks() {
  lock();
  const uint16_t n = static_cast<uint16_t>(chunks_.size());
  unlock();
  return n;
}

uint16_t QRBLEClient::totalChunks() {
  lock();
  const uint16_t n = chunksTotal_;
  unlock();
  return n;
}

void QRBLEClient::onScanResult(BLEAdvertisedDevice device) {
  if (found_) return;
  if (device.haveName() && device.getName() == kDeviceName) {
    lock();
    found_ = true;
    foundAddr_ = device.getAddress().toString();
    foundType_ = device.getAddressType();
    unlock();
    Serial.println("[BLE] found M5Paper-QR");
  }
}

void QRBLEClient::onStatusNotify(uint8_t* data, size_t len) {
  String s;
  s.reserve(len);
  for (size_t i = 0; i < len; ++i) s += static_cast<char>(data[i]);
  lock();
  statusText_ = s;
  statusChanged_ = true;
  unlock();
  Serial.printf("[BLE] status=%s\n", s.c_str());
}

void QRBLEClient::onMetadataNotify(uint8_t* data, size_t len) {
  String s;
  s.reserve(len);
  for (size_t i = 0; i < len; ++i) s += static_cast<char>(data[i]);
  lock();
  metadataRaw_ = s;
  metadataChanged_ = true;
  unlock();
  Serial.println("[BLE] metadata received");
}

void QRBLEClient::onDataNotify(uint8_t* data, size_t len) {
  if (len < 4) return;
  const uint16_t index = static_cast<uint16_t>((data[0] << 8) | data[1]);
  const uint16_t total = static_cast<uint16_t>((data[2] << 8) | data[3]);
  const size_t payloadLen = len - 4;

  lock();
  if (total == 0 || index >= total) { unlock(); return; }
  if (chunks_.find(index) != chunks_.end()) { unlock(); return; }
  if (chunksBytes_ + payloadLen > MAX_QR_PAYLOAD) {
    payloadTooLarge_ = true;
    unlock();
    return;
  }
  chunks_[index].assign(data + 4, data + len);
  chunksBytes_ += payloadLen;
  if (chunksTotal_ == 0 || total != chunksTotal_) chunksTotal_ = total;
  lastChunkMs_ = millis();
  const uint16_t received = static_cast<uint16_t>(chunks_.size());
  unlock();
  Serial.printf("[BLE] chunk %u/%u\n", received, total);
  if (received == total) {
    lock();
    transferComplete_ = true;
    unlock();
  }
}

void QRBLEClient::onConnectCallback() {
  lock();
  connected_ = true;
  disconnected_ = false;
  unlock();
}

void QRBLEClient::onDisconnectCallback() {
  lock();
  disconnected_ = true;
  connected_ = false;
  unlock();
  Serial.println("[BLE] disconnected");
}

void QRBLEClient::update() {
  switch (phase_) {
    case Phase::Scanning: {
      bool found = false;
      lock();
      found = found_;
      unlock();
      if (found) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        Serial.println("[BLE] stop scan");

        phase_ = Phase::Connecting;
        client_ = BLEDevice::createClient();
        client_->setClientCallbacks(clientCallbacks_);

        if (!client_->connect(BLEAddress(foundAddr_), foundType_)) {
          Serial.println("[BLE] connect failed");
          error_ = Error::ConnectFailed;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        Serial.println("[BLE] connected");

        BLERemoteService* service = client_->getService(kServiceUUID);
        if (!service) {
          Serial.println("[BLE] service not found");
          error_ = Error::ServiceNotFound;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        Serial.println("[BLE] service matched");

        BLERemoteCharacteristic* status = service->getCharacteristic(kStatusUUID);
        BLERemoteCharacteristic* meta = service->getCharacteristic(kMetadataUUID);
        BLERemoteCharacteristic* data = service->getCharacteristic(kDataUUID);
        if (!status || !meta || !data) {
          Serial.println("[BLE] characteristic not found");
          error_ = Error::SubscribeFailed;
          teardown();
          phase_ = Phase::Failed;
          break;
        }

        status->registerForNotify(
            [this](BLERemoteCharacteristic*, uint8_t* p, size_t l, bool) {
              onStatusNotify(p, l);
            });
        Serial.println("[BLE] subscribed STATUS");
        meta->registerForNotify(
            [this](BLERemoteCharacteristic*, uint8_t* p, size_t l, bool) {
              onMetadataNotify(p, l);
            });
        data->registerForNotify(
            [this](BLERemoteCharacteristic*, uint8_t* p, size_t l, bool) {
              onDataNotify(p, l);
            });
        Serial.println("[BLE] subscribed DATA");

        // METADATA tambien puede ser leida (no solo notificada).
        const std::string m = meta->readValue();
        if (!m.empty()) {
          lock();
          metadataRaw_ = String(m.c_str());
          metadataChanged_ = true;
          unlock();
          Serial.println("[BLE] metadata received");
        }
        waitStartMs_ = millis();
        phase_ = Phase::Waiting;
      } else if (millis() - scanStartMs_ > kScanTimeoutMs) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        error_ = Error::ScanTimeout;
        Serial.println("[BLE] scan timeout");
        teardown();
        phase_ = Phase::Failed;
      }
      break;
    }

    case Phase::Waiting: {
      bool metaChanged = false, firstChunk = false;
      lock();
      metaChanged = metadataChanged_;
      firstChunk = !chunks_.empty();
      unlock();
      if (metaChanged) {
        lock();
        const String raw = metadataRaw_;
        metadataChanged_ = false;
        unlock();
        if (!parseMetadata(raw, metadata_)) {
          error_ = Error::InvalidTransfer;
          Serial.println("[BLE] bad metadata");
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        if (metadata_.size > MAX_QR_PAYLOAD) {
          error_ = Error::PayloadTooLarge;
          Serial.println("[BLE] payload too large");
          teardown();
          phase_ = Phase::Failed;
          break;
        }
        metadataReady_ = true;
        Serial.printf("[BLE] format=%s\n", metadata_.format.c_str());
        Serial.printf("[BLE] type=%s\n", metadata_.type.c_str());
        Serial.printf("[BLE] size=%u\n", static_cast<unsigned>(metadata_.size));
      }
      String status;
      bool changed = false;
      lock();
      changed = statusChanged_;
      if (changed) {
        status = statusText_;
        statusChanged_ = false;
      }
      unlock();
      if (changed) {
        if (status == "PAYLOAD_TOO_LARGE") {
          error_ = Error::PayloadTooLarge;
          teardown();
          phase_ = Phase::Failed;
          break;
        }
      }
      if (firstChunk || (changed && status == "TRANSFER_START")) {
        lastChunkMs_ = millis();
        phase_ = Phase::Receiving;
      } else if (millis() - waitStartMs_ > kWaitTimeoutMs) {
        error_ = Error::TransferTimeout;
        teardown();
        phase_ = Phase::Failed;
      }
      break;
    }

    case Phase::Receiving: {
      bool tooLarge = false, disconnected = false, complete = false;
      lock();
      tooLarge = payloadTooLarge_;
      disconnected = disconnected_;
      complete = transferComplete_;
      unlock();
      if (tooLarge) {
        error_ = Error::PayloadTooLarge;
        teardown();
        phase_ = Phase::Failed;
        break;
      }
      if (disconnected) {
        error_ = Error::Disconnected;
        teardown();
        phase_ = Phase::Failed;
        break;
      }
      String status;
      bool changed = false;
      lock();
      changed = statusChanged_;
      if (changed) {
        status = statusText_;
        statusChanged_ = false;
      }
      unlock();
      if (changed && status == "PAYLOAD_TOO_LARGE") {
        error_ = Error::PayloadTooLarge;
        teardown();
        phase_ = Phase::Failed;
        break;
      }
      if (complete) finalizeTransfer();
      else if (millis() - lastChunkMs_ > kTransferTimeoutMs) {
        error_ = Error::TransferTimeout;
        teardown();
        phase_ = Phase::Failed;
      }
      break;
    }

    default:
      break;
  }
}

void QRBLEClient::finalizeTransfer() {
  Serial.println("[BLE] transfer complete");
  std::map<uint16_t, std::vector<uint8_t>> received;
  lock();
  received.swap(chunks_);
  transferComplete_ = false;
  chunksBytes_ = 0;
  unlock();

  std::vector<uint8_t> assembled;
  const size_t expected = metadataReady_ ? metadata_.size : 0;
  if (expected > 0 && expected <= MAX_QR_PAYLOAD) {
    assembled.reserve(expected);
  }
  for (auto& kv : received) {
    assembled.insert(assembled.end(), kv.second.begin(), kv.second.end());
  }
  received.clear();

  const size_t receivedSize = assembled.size();
  const bool sizeOk = metadataReady_ && receivedSize == metadata_.size;
  bool hashOk = false;
  if (sizeOk) {
    const String digest = hexSha256(assembled.data(), assembled.size());
    hashOk = digest.length() == 64 && digest.equalsIgnoreCase(metadata_.sha256);
  }

  if (sizeOk && hashOk) {
    Serial.println("[BLE] SHA256 OK");
    payload_.format = metadata_.format;
    payload_.type = metadata_.type;
    payload_.data = std::move(assembled);
    payload_.valid = true;
    payloadReady_ = true;
    teardown();
    phase_ = Phase::Success;
  } else {
    Serial.println("[BLE] SHA256 mismatch or size mismatch");
    assembled.clear();
    assembled.shrink_to_fit();
    error_ = Error::InvalidTransfer;
    teardown();
    phase_ = Phase::Failed;
  }
}

void QRBLEClient::teardown() {
  Serial.println("[BLE] disconnect");
  if (scan_ && scanning_) {
    scan_->stop();
    scanning_ = false;
  }
  if (client_ && client_->isConnected()) {
    client_->disconnect();
  }
  lock();
  chunks_.clear();
  chunksTotal_ = 0;
  chunksBytes_ = 0;
  transferComplete_ = false;
  payloadTooLarge_ = false;
  connected_ = false;
  disconnected_ = false;
  found_ = false;
  unlock();

  if (client_) {
    delete client_;
    client_ = nullptr;
  }
  if (bleOn_) {
    BLEDevice::deinit(false);
    bleOn_ = false;
  }
}

}  // namespace qr_ble
