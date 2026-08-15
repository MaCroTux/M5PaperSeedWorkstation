#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>

// Conexion WiFi en modo estacion (STA) para "CONSULTAR SALDO".
// El dispositivo abandona el modo air-gapped solo durante esta operacion.
// Las credenciales del ultimo punto de acceso se guardan en NVS ("wifi").

namespace wifi_sta {

inline bool hasSaved() {
  Preferences p;
  if (!p.begin("wifi", true)) return false;
  const bool ok = p.getString("ssid", "").length() > 0;
  p.end();
  return ok;
}

inline String savedSsid() {
  Preferences p;
  if (!p.begin("wifi", true)) return "";
  const String s = p.getString("ssid", "");
  p.end();
  return s;
}

inline String savedPass() {
  Preferences p;
  if (!p.begin("wifi", true)) return "";
  const String s = p.getString("pass", "");
  p.end();
  return s;
}

inline bool save(const String& ssid, const String& pass) {
  Preferences p;
  if (!p.begin("wifi", false)) return false;
  p.putString("ssid", ssid);
  p.putString("pass", pass);
  p.end();
  return true;
}

inline bool erase() {
  Preferences p;
  if (!p.begin("wifi", false)) return false;
  const bool ok = p.remove("ssid") && p.remove("pass");
  p.end();
  return ok;
}

// Conecta en modo STA esperando hasta timeoutMs. Devuelve true si conecto.
inline bool connect(const String& ssid, const String& pass, uint32_t timeoutMs = 15000) {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);
  WiFi.begin(ssid.c_str(), pass.c_str());
  const uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(100);
  }
  return WiFi.status() == WL_CONNECTED;
}

inline void disconnect() {
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
}

// Escanea redes. Devuelve el numero de redes encontradas.
inline int scan() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);
  return WiFi.scanNetworks();
}

inline String ssidAt(int i) { return WiFi.SSID(i); }
inline int32_t rssiAt(int i) { return WiFi.RSSI(i); }

}  // namespace wifi_sta
