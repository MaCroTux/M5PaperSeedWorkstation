#include "qr_cam_client.hpp"

namespace qr_cam {

namespace {
constexpr uint32_t kScanTimeoutMs = 15000;

// Parsea "<index>:<data>" guardando el chunk. Devuelve false si el indice es
// invalido o el chunk excederia MAX_QR_PAYLOAD.
bool parseHexIndex(const std::string& s, uint16_t* out) {
  if (s.empty()) return false;
  uint32_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<uint32_t>(c - '0');
    if (v > 65535) return false;
  }
  *out = static_cast<uint16_t>(v);
  return true;
}
}  // namespace

QRCamClient::QRCamClient() {
  mux_ = xSemaphoreCreateMutex();
  scanCallbacks_ = new ScanCallbacks(this);
  clientCallbacks_ = new ClientCallbacks(this);
}

QRCamClient::~QRCamClient() {
  teardown();
  delete scanCallbacks_;
  delete clientCallbacks_;
  if (mux_) vSemaphoreDelete(mux_);
  mux_ = nullptr;
}

void QRCamClient::start() {
  if (phase_ == Phase::Scanning || phase_ == Phase::Connecting ||
      phase_ == Phase::Connected || phase_ == Phase::WaitingQr ||
      phase_ == Phase::Receiving) return;

  teardown();
  lock();
  rxBuffer_.clear();
  found_ = connected_ = disconnected_ = false;
  foundAddr_.clear();
  unlock();

  chunks_.clear();
  expectedSize_ = 0;
  expectedChunks_ = 0;
  chunksBytes_ = 0;
  transferActive_ = false;
  qrend_ = false;
  payloadTooLarge_ = false;
  payload_.clear();
  payloadReady_ = false;
  error_ = Error::None;

  Serial.println("[CAM] scanning");
  NimBLEDevice::init("M5Paper-QR-CAM-Client");
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

void QRCamClient::cancel() {
  if (phase_ == Phase::Off || phase_ == Phase::Cancelled) return;
  Serial.println("[CAM] cancel");
  teardown();
  phase_ = Phase::Cancelled;
}

void QRCamClient::clear() {
  teardown();
  chunks_.clear();
  expectedSize_ = 0;
  expectedChunks_ = 0;
  chunksBytes_ = 0;
  transferActive_ = false;
  qrend_ = false;
  payloadTooLarge_ = false;
  payload_.clear();
  payloadReady_ = false;
  error_ = Error::None;
  phase_ = Phase::Off;
}

std::vector<uint8_t> QRCamClient::takePayload() {
  payloadReady_ = false;
  return std::move(payload_);
}

void QRCamClient::onScanResult(NimBLEAdvertisedDevice* device) {
  if (found_) return;
  if (device->haveName() && device->getName() == kDeviceName) {
    lock();
    found_ = true;
    foundAddr_ = device->getAddress().toString();
    foundType_ = device->getAddress().getType();
    unlock();
    Serial.println("[CAM] found M5Paper-QR-CAM");
  }
}

void QRCamClient::onConnectCallback(NimBLEClient*) {
  lock(); connected_ = true; disconnected_ = false; unlock();
}

void QRCamClient::onDisconnectCallback(NimBLEClient*) {
  lock(); disconnected_ = true; connected_ = false; unlock();
  Serial.println("[CAM] disconnected");
}

void QRCamClient::onTxNotify(uint8_t* data, size_t len) {
  lock();
  rxBuffer_.append(reinterpret_cast<const char*>(data), len);
  unlock();
}

void QRCamClient::drainLines() {
  std::string buf;
  lock();
  buf.swap(rxBuffer_);
  unlock();
  if (buf.empty()) return;

  size_t start = 0;
  while (start < buf.size()) {
    const size_t nl = buf.find('\n', start);
    const std::string line =
        (nl == std::string::npos) ? buf.substr(start) : buf.substr(start, nl - start);
    processLine(line);
    if (nl == std::string::npos) break;
    start = nl + 1;
  }
}

void QRCamClient::processLine(const std::string& raw) {
  std::string line = raw;
  while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
    line.pop_back();
  if (line.empty()) return;

  if (line == "QREND") {
    if (transferActive_) { qrend_ = true; Serial.println("[CAM] QREND"); }
    return;
  }

  if (line.compare(0, 8, "QRBEGIN:") == 0) {
    const size_t c1 = line.find(':');
    const size_t c2 = line.find(':', c1 + 1);
    if (c1 == std::string::npos || c2 == std::string::npos) {
      error_ = Error::InvalidTransfer;
      return;
    }
    const std::string sizeStr = line.substr(c1 + 1, c2 - c1 - 1);
    const std::string chunksStr = line.substr(c2 + 1);
    const size_t size = strtoul(sizeStr.c_str(), nullptr, 10);
    const uint32_t chunks = strtoul(chunksStr.c_str(), nullptr, 10);
    if (size == 0 || size > MAX_QR_PAYLOAD ||
        chunks == 0 || chunks > MAX_QR_CHUNKS) {
      error_ = Error::InvalidTransfer;
      Serial.println("[CAM] QRBEGIN fuera de limites");
      return;
    }
    beginTransfer(size, static_cast<uint16_t>(chunks));
    return;
  }

  // Chunk "<index>:<data>".
  if (!transferActive_) return;
  const size_t c = line.find(':');
  if (c == std::string::npos) return;
  uint16_t index = 0;
  if (!parseHexIndex(line.substr(0, c), &index) || index >= expectedChunks_) {
    error_ = Error::InvalidTransfer;
    return;
  }
  const std::string data = line.substr(c + 1);
  if (chunks_.find(index) == chunks_.end()) {
    if (chunksBytes_ + data.size() > MAX_QR_PAYLOAD) {
      payloadTooLarge_ = true;
      return;
    }
    chunks_[index].assign(data.begin(), data.end());
    chunksBytes_ += data.size();
    Serial.printf("[CAM] chunk %u/%u\n", static_cast<unsigned>(chunks_.size()),
                  expectedChunks_);
  }
}

void QRCamClient::beginTransfer(size_t size, uint16_t chunks) {
  chunks_.clear();
  expectedSize_ = size;
  expectedChunks_ = chunks;
  chunksBytes_ = 0;
  transferActive_ = true;
  qrend_ = false;
  payloadTooLarge_ = false;
  transferStartMs_ = millis();
  Serial.printf("[CAM] QRBEGIN size=%u chunks=%u\n", static_cast<unsigned>(size),
                static_cast<unsigned>(chunks));
  phase_ = Phase::Receiving;
}

void QRCamClient::finalizeTransfer() {
  std::vector<uint8_t> assembled;
  assembled.reserve(expectedSize_);
  for (auto& kv : chunks_) {
    assembled.insert(assembled.end(), kv.second.begin(), kv.second.end());
  }

  const bool sizeOk = assembled.size() == expectedSize_;
  if (sizeOk) {
    Serial.println("[CAM] transferencia OK");
    payload_ = std::move(assembled);
    payloadReady_ = true;
    teardown();
    phase_ = Phase::Complete;
  } else {
    Serial.printf("[CAM] QR_TRANSFER_ERROR (size %u != %u)\n",
                  static_cast<unsigned>(assembled.size()),
                  static_cast<unsigned>(expectedSize_));
    assembled.clear();
    error_ = Error::InvalidTransfer;
    teardown();
    phase_ = Phase::Error;
  }
}

void QRCamClient::update() {
  switch (phase_) {
    case Phase::Scanning: {
      bool found = false;
      lock(); found = found_; unlock();
      if (found) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        Serial.println("[CAM] stop scan");
        phase_ = Phase::Connecting;
        client_ = NimBLEDevice::createClient();
        client_->setClientCallbacks(clientCallbacks_, false);
        if (!client_->connect(NimBLEAddress(foundAddr_, foundType_))) {
          error_ = Error::ConnectFailed;
          teardown();
          phase_ = Phase::Error;
          break;
        }
        Serial.println("[CAM] connected");
        NimBLERemoteService* service = client_->getService(kServiceUUID);
        if (!service) {
          error_ = Error::ServiceNotFound;
          teardown();
          phase_ = Phase::Error;
          break;
        }
        NimBLERemoteCharacteristic* rx = service->getCharacteristic(kRxUUID);
        NimBLERemoteCharacteristic* tx = service->getCharacteristic(kTxUUID);
        if (!rx || !tx) {
          error_ = Error::SubscribeFailed;
          teardown();
          phase_ = Phase::Error;
          break;
        }
        if (!tx->subscribe(true, [this](NimBLERemoteCharacteristic*,
                                        uint8_t* p, size_t l, bool) {
              onTxNotify(p, l);
            })) {
          error_ = Error::SubscribeFailed;
          teardown();
          phase_ = Phase::Error;
          break;
        }
        Serial.println("[CAM] subscribed TX");
        // Comando inicial: pedir estado a la camara (STATUS -> SCANNING).
        if (!rx->writeValue(std::string("STATUS"), false)) {
          error_ = Error::WriteFailed;
          teardown();
          phase_ = Phase::Error;
          break;
        }
        Serial.println("[CAM] STATUS sent");
        phase_ = Phase::Connected;
      } else if (millis() - scanStartMs_ > kScanTimeoutMs) {
        if (scan_ && scanning_) { scan_->stop(); scanning_ = false; }
        error_ = Error::ScanTimeout;
        teardown();
        phase_ = Phase::Error;
      }
      break;
    }

    case Phase::Connected:
      phase_ = Phase::WaitingQr;
      break;

    case Phase::WaitingQr: {
      bool dis = false;
      lock(); dis = disconnected_; unlock();
      if (dis) { error_ = Error::Disconnected; teardown(); phase_ = Phase::Error; break; }
      drainLines();
      if (transferActive_) phase_ = Phase::Receiving;
      break;
    }

    case Phase::Receiving: {
      bool dis = false;
      lock(); dis = disconnected_; unlock();
      if (dis) { error_ = Error::Disconnected; teardown(); phase_ = Phase::Error; break; }
      drainLines();
      if (payloadTooLarge_) {
        error_ = Error::PayloadTooLarge;
        teardown();
        phase_ = Phase::Error;
        break;
      }
      if (qrend_) {
        qrend_ = false;
        finalizeTransfer();
        break;
      }
      if (millis() - transferStartMs_ > kTransferTimeoutMs) {
        error_ = Error::TransferTimeout;
        teardown();
        phase_ = Phase::Error;
      }
      break;
    }

    default:
      break;
  }
}

void QRCamClient::teardown() {
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
  rxBuffer_.clear();
  unlock();
  transferActive_ = false;
  qrend_ = false;
  payloadTooLarge_ = false;
  chunks_.clear();
  if (bleOn_) { NimBLEDevice::deinit(true); bleOn_ = false; }
}

}  // namespace qr_cam
