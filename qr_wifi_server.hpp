#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <vector>

// Servidor WiFi (modo Access Point) para recibir un archivo o contenido de QR
// desde un movil, sin depender de la Raspberry Pi.
//
// Flujo: el M5Paper crea un AP "M5Paper-QR"; el movil se conecta, abre
// http://192.168.4.1 y pega texto o sube un archivo. El contenido se entrega
// como un payload crudo (format/type + bytes). La integridad la garantiza TCP
// (no hay terceros); el contenido (p.ej. PSBT) se validara despues en la app.
//
// El telefono es un dispositivo de entrada NO confiable; aqui solo se recoge
// el dato, no se interpreta.

namespace qr_wifi {

constexpr size_t MAX_PAYLOAD = 32768;
constexpr char kApSsid[] = "M5Paper-QR";
constexpr char kApPassword[] = "m5paper123";

const char kHtmlPage[] = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M5Paper</title></head>
<body style="font-family:sans-serif;max-width:32em;margin:1em auto;padding:1em">
<h1>M5Paper Seed Workstation</h1>
<h2>1. Pegar contenido de QR</h2>
<textarea id="txt" rows="6" style="width:100%" placeholder="Pega aqui el texto del QR..."></textarea><br>
<button onclick="paste()">Enviar texto</button>
<hr>
<h2>2. Subir archivo (PSBT, etc.)</h2>
<input type="file" id="f"><br><br>
<button onclick="upload()">Subir archivo</button>
<hr>
<div id="st"></div>
<script>
function st(m){document.getElementById('st').textContent=m;}
async function paste(){
 var t=document.getElementById('txt').value;
 if(!t){st('Vacio');return;}
 st('Enviando...');
 try{var r=await fetch('/paste',{method:'POST',headers:{'Content-Type':'text/plain'},body:t});st(r.ok?'OK':'ERROR '+r.status);}catch(e){st('Fallo: '+e);}
}
async function upload(){
 var f=document.getElementById('f').files[0];
 if(!f){st('Elige archivo');return;}
 st('Enviando...');
 var fd=new FormData(); fd.append('file',f);
 try{var r=await fetch('/upload',{method:'POST',body:fd});st(r.ok?'OK':'ERROR '+r.status);}catch(e){st('Fallo: '+e);}
}
</script>
</body></html>
)rawliteral";

enum class Phase : uint8_t { Idle, Starting, Waiting, Received, Failed, Cancelled };

class QRWiFiServer {
public:
  QRWiFiServer() : server_(80) {}

  void start() {
    if (phase_ == Phase::Starting || phase_ == Phase::Waiting) return;
    teardown();
    data_.clear();
    format_ = ""; type_ = "";
    ready_ = false;
    payloadTooLarge_ = false;
    phase_ = Phase::Starting;

    Serial.println("[WIFI] starting AP");
    WiFi.mode(WIFI_AP);
    if (!WiFi.softAP(kApSsid, kApPassword)) {
      Serial.println("[WIFI] AP failed");
      phase_ = Phase::Failed;
      return;
    }
    server_.on("/", HTTP_GET, [this]() { handleRoot(); });
    server_.on("/paste", HTTP_POST, [this]() { handlePaste(); });
    server_.on("/upload", HTTP_POST,
               [this]() { handleUploadDone(); },
               [this]() { handleUpload(); });
    server_.begin();
    Serial.print("[WIFI] AP IP: ");
    Serial.println(WiFi.softAPIP());
    phase_ = Phase::Waiting;
  }

  void update() {
    if (phase_ == Phase::Waiting) server_.handleClient();
  }

  void cancel() {
    if (phase_ == Phase::Idle || phase_ == Phase::Cancelled) return;
    Serial.println("[WIFI] cancel");
    teardown();
    phase_ = Phase::Cancelled;
  }

  void clear() {
    teardown();
    data_.clear();
    data_.shrink_to_fit();
    format_ = ""; type_ = "";
    ready_ = false;
    payloadTooLarge_ = false;
    phase_ = Phase::Idle;
  }

  Phase phase() const { return phase_; }
  bool ready() const { return ready_; }
  const std::vector<uint8_t>& data() const { return data_; }
  String format() const { return format_; }
  String type() const { return type_; }

private:
  void teardown() {
    if (phase_ == Phase::Waiting || phase_ == Phase::Starting) {
      server_.stop();
    }
    if (WiFi.getMode() != WIFI_OFF) {
      WiFi.softAPdisconnect(true);
      WiFi.mode(WIFI_OFF);
    }
  }

  void handleRoot() {
    server_.send(200, "text/html", kHtmlPage);
  }

  void handlePaste() {
    const String body = server_.arg("plain");
    const size_t n = body.length();
    if (n == 0) { server_.send(400, "text/plain", "EMPTY"); return; }
    if (n > MAX_PAYLOAD) { server_.send(413, "text/plain", "TOO LARGE"); return; }
    const uint8_t* p = reinterpret_cast<const uint8_t*>(body.c_str());
    data_.assign(p, p + n);
    format_ = "PLAIN"; type_ = "TEXT";
    ready_ = true;
    phase_ = Phase::Received;
    server_.send(200, "text/plain", "OK");
  }

  void handleUpload() {
    HTTPUpload& u = server_.upload();
    if (u.status == UPLOAD_FILE_START) {
      data_.clear();
      format_ = "BINARY"; type_ = "FILE";
      ready_ = false;
      payloadTooLarge_ = false;
    } else if (u.status == UPLOAD_FILE_WRITE) {
      if (payloadTooLarge_) return;
      if (data_.size() + u.currentSize > MAX_PAYLOAD) {
        payloadTooLarge_ = true;
        data_.clear();
        return;
      }
      data_.insert(data_.end(), u.buf, u.buf + u.currentSize);
    }
  }

  void handleUploadDone() {
    if (payloadTooLarge_) {
      payloadTooLarge_ = false;
      data_.clear();
      ready_ = false;
      server_.send(413, "text/plain", "TOO LARGE");
      return;
    }
    if (data_.empty()) { server_.send(400, "text/plain", "EMPTY"); return; }
    ready_ = true;
    phase_ = Phase::Received;
    server_.send(200, "text/plain", "OK");
  }

  Phase phase_ = Phase::Idle;
  WebServer server_;
  std::vector<uint8_t> data_;
  String format_;
  String type_;
  bool ready_ = false;
  bool payloadTooLarge_ = false;
};

}  // namespace qr_wifi
