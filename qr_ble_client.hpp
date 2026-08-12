#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <vector>
#include <map>
#include <string>

// Cliente BLE (NimBLE) para recibir un QR enviado por una Raspberry Pi Zero W
// (servidor GATT). Flujo: BLE ON -> scan -> connect -> subscribe
// STATUS/METADATA/DATA -> recibir METADATA -> recibir chunks DATA ->
// reconstruir -> verificar SIZE y SHA256 -> desconectar -> BLE OFF.
//
// Se usa NimBLE en vez de Bluedroid porque consume mucha menos RAM y evita los
// asserts internos de Bluedroid (GKI/BTA) que se producen en el M5Paper.
//
// Toda la logica de conexion se ejecuta desde update(), llamado desde loop().
// Las callbacks de notificacion (tarea de NimBLE) NO dibujan e-ink ni hacen
// cripto; solo guardan estado/datos bajo un mutex.
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
  Idle, Scanning, Connecting, Waiting, Receiving,
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
  void lock() { if (mux_) xSemaphoreTake(mux_, portMAX_DELAY); }
  void unlock() { if (mux_) xSemaphoreGive(mux_); }

  void onScanResult(NimBLEAdvertisedDevice* device);
  void onStatusNotify(uint8_t* data, size_t len);
  void onMetadataNotify(uint8_t* data, size_t len);
  void onDataNotify(uint8_t* data, size_t len);
  void onConnectCallback(NimBLEClient* client);
  void onDisconnectCallback(NimBLEClient* client);

  void teardown();
  void finalizeTransfer();

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
  uint8_t foundType_ = 0;

  // Recursos BLE.
  NimBLEScan* scan_ = nullptr;
  NimBLEClient* client_ = nullptr;
  bool bleOn_ = false;
  bool scanning_ = false;

  // Timeouts.
  uint32_t scanStartMs_ = 0;
  uint32_t waitStartMs_ = 0;
  uint32_t lastChunkMs_ = 0;

  class ScanCallbacks;
  class ClientCallbacks;
  ScanCallbacks* scanCallbacks_ = nullptr;
  ClientCallbacks* clientCallbacks_ = nullptr;
};

class QRBLEClient::ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
public:
  explicit ScanCallbacks(QRBLEClient* c) : client(c) {}
  void onResult(NimBLEAdvertisedDevice* device) override { client->onScanResult(device); }
private:
  QRBLEClient* client;
};

class QRBLEClient::ClientCallbacks : public NimBLEClientCallbacks {
public:
  explicit ClientCallbacks(QRBLEClient* c) : client(c) {}
  void onConnect(NimBLEClient* c) override { client->onConnectCallback(c); }
  void onDisconnect(NimBLEClient* c) override { client->onDisconnectCallback(c); }
private:
  QRBLEClient* client;
};

}  // namespace qr_ble
