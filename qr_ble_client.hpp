#pragma once
#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEClient.h>
#include <BLERemoteService.h>
#include <BLERemoteCharacteristic.h>
#include <BLEAdvertisedDevice.h>
#include <vector>
#include <map>
#include <string>

// Cliente BLE para recibir un QR enviado por una Raspberry Pi Zero W (servidor
// GATT). Flujo: BLE ON -> scan -> connect -> subscribe STATUS/METADATA/DATA ->
// recibir METADATA -> recibir chunks DATA -> reconstruir -> verificar SIZE y
// SHA256 -> desconectar -> BLE OFF.
//
// Las callbacks BLE se ejecutan en la tarea de Bluedroid y NO dibujan e-ink ni
// hacen cripto. Solo guardan estado/datos bajo un mutex; el bucle principal
// (update()) procesa el flujo como una maquina de estados y actualiza la UI.
//
// La Pi es un dispositivo de entrada NO confiable: el SHA256 solo protege el
// transporte. Aqui no se interpreta el contenido; solo se entrega un QRPayload.

namespace qr_ble {

constexpr size_t MAX_QR_PAYLOAD = 32768;
constexpr char kServiceUUID[]  = "f0e10001-6c7a-4f6a-9c11-7d5965000001";
constexpr char kStatusUUID[]   = "f0e10002-6c7a-4f6a-9c11-7d5965000001";
constexpr char kMetadataUUID[] = "f0e10003-6c7a-4f6a-9c11-7d5965000001";
constexpr char kDataUUID[]     = "f0e10004-6c7a-4f6a-9c11-7d5965000001";
constexpr char kDeviceName[]   = "M5Paper-QR";

struct QRMetadata {
  String format;
  String type;
  size_t size = 0;
  String sha256;
  bool complete = false;
};

struct QRPayload {
  String format;
  String type;
  std::vector<uint8_t> data;
  bool valid = false;
};

enum class Phase : uint8_t {
  Idle, Scanning, Connecting, Subscribing, Waiting, Receiving,
  Success, Failed, Cancelled
};

enum class Error : uint8_t {
  None, BleInit, ScanTimeout, ConnectTimeout, ConnectFailed,
  ServiceNotFound, SubscribeFailed, Disconnected,
  PayloadTooLarge, InvalidTransfer, TransferTimeout
};

class QRBLEClient {
public:
  QRBLEClient();
  ~QRBLEClient();

  void start();   // BLE ON + scan (no bloqueante)
  void cancel();  // stop scan + disconnect + liberar + BLE OFF
  void update();  // maquina de estados; llamar desde loop()
  void clear();   // liberar payload y reiniciar a Idle

  Phase phase() const { return phase_; }
  Error error() const { return error_; }
  String statusText();
  bool hasPayload() const { return payloadReady_; }
  const QRPayload& payload() const { return payload_; }
  QRPayload takePayload();

  uint16_t receivedChunks();
  uint16_t totalChunks();
  const QRMetadata& metadata() const { return metadata_; }

private:
  enum class SetupResult : uint8_t { None, Ok, ConnectFailed,
                                     ServiceNotFound, SubscribeFailed };

  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }

  void onScanResult(BLEAdvertisedDevice device);
  void onStatusNotify(uint8_t* data, size_t len);
  void onMetadataNotify(uint8_t* data, size_t len);
  void onDataNotify(uint8_t* data, size_t len);
  void onConnectCallback();
  void onDisconnectCallback();

  void teardown();
  void finalizeTransfer();
  void runConnect();
  static void connectTaskEntry(void* arg);

  // Estado manejado solo desde update()/loop (mono-hilo).
  Phase phase_ = Phase::Idle;
  Error error_ = Error::None;
  QRMetadata metadata_;
  bool metadataReady_ = false;
  QRPayload payload_;
  bool payloadReady_ = false;

  // Estado compartido con las callbacks (protegido por mux_).
  SemaphoreHandle_t mux_ = nullptr;
  String statusText_;
  bool statusChanged_ = false;
  String metadataRaw_;
  bool metadataChanged_ = false;
  std::map<uint16_t, std::vector<uint8_t>> chunks_;
  uint16_t chunksTotal_ = 0;
  size_t chunksBytes_ = 0;
  bool transferComplete_ = false;
  bool payloadTooLarge_ = false;
  bool connected_ = false;
  bool disconnected_ = false;
  bool found_ = false;
  std::string foundAddr_;
  esp_ble_addr_type_t foundType_ = BLE_ADDR_TYPE_PUBLIC;

  // Recursos y tarea de conexion.
  BLEScan* scan_ = nullptr;
  BLEClient* client_ = nullptr;
  bool bleOn_ = false;
  bool scanning_ = false;
  TaskHandle_t taskHandle_ = nullptr;
  bool taskRunning_ = false;
  bool abortRequested_ = false;
  bool taskDone_ = true;
  bool connectOk_ = false;
  SetupResult setupResult_ = SetupResult::None;

  // Timeouts.
  uint32_t scanStartMs_ = 0;
  uint32_t connectStartMs_ = 0;
  uint32_t waitStartMs_ = 0;
  uint32_t lastChunkMs_ = 0;

  class ScanCallbacks;
  class ClientCallbacks;
  ScanCallbacks* scanCallbacks_ = nullptr;
  ClientCallbacks* clientCallbacks_ = nullptr;
};

class QRBLEClient::ScanCallbacks : public BLEAdvertisedDeviceCallbacks {
public:
  explicit ScanCallbacks(QRBLEClient* c) : client(c) {}
  void onResult(BLEAdvertisedDevice device) override { client->onScanResult(device); }
private:
  QRBLEClient* client;
};

class QRBLEClient::ClientCallbacks : public BLEClientCallbacks {
public:
  explicit ClientCallbacks(QRBLEClient* c) : client(c) {}
  void onConnect(BLEClient*) override { client->onConnectCallback(); }
  void onDisconnect(BLEClient*) override { client->onDisconnectCallback(); }
private:
  QRBLEClient* client;
};

}  // namespace qr_ble
