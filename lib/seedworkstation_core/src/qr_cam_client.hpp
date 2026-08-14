#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <vector>
#include <map>
#include <string>

// Cliente BLE (M5Paper) para un modulo ESP32-CAM + OV2640 que actua como
// coprocesador de vision. La camara lee un QR, lo decodifica y envia el payload
// YA decodificado (opaco) por BLE. El M5Paper no recibe imagenes.
//
// Protocolo (estilo Nordic UART Service):
//   - El M5Paper es Central/GATT Client; la camara es Peripheral/GATT Server.
//   - RX (WRITE)   : comandos M5Paper -> camara (PING, STATUS).
//   - TX (NOTIFY)  : respuesta/transferencia camara -> M5Paper.
//
// Transferencia fragmentada por tamano limitado de las notificaciones:
//   QRBEGIN:<size>:<chunks>
//   <index>:<data>
//   ...
//   QREND
//
// Reconstruccion: se almacenan los chunks por indice (no se asume orden ni
// integridad solo por recibir QREND), se concatenan y se exige
// reconstructed.size() == expectedSize. Si no coincide -> QR_TRANSFER_ERROR.
//
// La camara es NO confiable: aqui solo se valida el transporte y se entrega el
// payload opaco al QR dispatcher del M5Paper (que lo parsea/valida como cualquier
// QR de otra fuente). Nada de seed/claves privadas viaja hacia la camara.

namespace qr_cam {

constexpr size_t MAX_QR_PAYLOAD = 32768;
constexpr uint16_t MAX_QR_CHUNKS = 1024;
constexpr uint32_t kTransferTimeoutMs = 5000;

constexpr char kDeviceName[]  = "M5Paper-QR-CAM";
constexpr char kServiceUUID[] = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
constexpr char kRxUUID[]      = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E";
constexpr char kTxUUID[]      = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E";

enum class Phase : uint8_t {
  Off, Scanning, Connecting, Connected, WaitingQr, Receiving,
  Complete, Error, Cancelled
};

enum class Error : uint8_t {
  None, BleInit, ScanTimeout, ConnectFailed, ServiceNotFound,
  SubscribeFailed, Disconnected, PayloadTooLarge, InvalidTransfer,
  TransferTimeout, WriteFailed
};

class QRCamClient {
public:
  QRCamClient();
  ~QRCamClient();

  void start();   // BLE ON + scan (no bloqueante)
  void cancel();  // stop scan + disconnect + liberar + BLE OFF
  void update();  // maquina de estados; llamar desde loop()
  void clear();   // liberar payload y reiniciar a Off

  Phase phase() const { return phase_; }
  Error error() const { return error_; }
  bool hasPayload() const { return payloadReady_; }
  const std::vector<uint8_t>& payload() const { return payload_; }
  std::vector<uint8_t> takePayload();
  uint16_t receivedChunks() const { return static_cast<uint16_t>(chunks_.size()); }
  uint16_t totalChunks() const { return expectedChunks_; }

private:
  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }

  void onScanResult(NimBLEAdvertisedDevice* device);
  void onConnectCallback(NimBLEClient* client);
  void onDisconnectCallback(NimBLEClient* client);
  void onTxNotify(uint8_t* data, size_t len);

  // Solo desde update()/loop (mono-hilo).
  void drainLines();
  void processLine(const std::string& raw);
  void beginTransfer(size_t size, uint16_t chunks);
  void finalizeTransfer();
  void teardown();

  // Estado solo de update()/loop (mono-hilo).
  Phase phase_ = Phase::Off;
  Error error_ = Error::None;
  std::map<uint16_t, std::vector<uint8_t>> chunks_;
  size_t expectedSize_ = 0;
  uint16_t expectedChunks_ = 0;
  size_t chunksBytes_ = 0;
  bool transferActive_ = false;
  bool qrend_ = false;
  bool payloadTooLarge_ = false;
  std::vector<uint8_t> payload_;
  bool payloadReady_ = false;

  // Estado compartido con callbacks (protegido por mux_).
  SemaphoreHandle_t mux_ = nullptr;
  std::string rxBuffer_;
  bool connected_ = false;
  bool disconnected_ = false;
  bool found_ = false;
  std::string foundAddr_;
  uint8_t foundType_ = 0;

  // Recursos BLE.
  NimBLEScan* scan_ = nullptr;
  NimBLEClient* client_ = nullptr;
  bool bleOn_ = false;
  bool scanning_ = false;

  // Timeouts.
  uint32_t scanStartMs_ = 0;
  uint32_t transferStartMs_ = 0;

  class ScanCallbacks;
  class ClientCallbacks;
  ScanCallbacks* scanCallbacks_ = nullptr;
  ClientCallbacks* clientCallbacks_ = nullptr;
};

class QRCamClient::ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
public:
  explicit ScanCallbacks(QRCamClient* c) : client(c) {}
  void onResult(NimBLEAdvertisedDevice* device) override { client->onScanResult(device); }
private:
  QRCamClient* client;
};

class QRCamClient::ClientCallbacks : public NimBLEClientCallbacks {
public:
  explicit ClientCallbacks(QRCamClient* c) : client(c) {}
  void onConnect(NimBLEClient* c) override { client->onConnectCallback(c); }
  void onDisconnect(NimBLEClient* c) override { client->onDisconnectCallback(c); }
private:
  QRCamClient* client;
};

}  // namespace qr_cam
