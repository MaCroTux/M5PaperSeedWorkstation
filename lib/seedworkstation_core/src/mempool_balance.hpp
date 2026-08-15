#pragma once
#include <Arduino.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

// Consulta de saldo contra mempool.space (API compatible Esplora).
// Solo se envia la direccion (datos publicos); nunca claves ni la seed.
// TLS con el certificado raiz de Let's Encrypt (ISRG Root X1).

namespace mempool_balance {

// ISRG Root X1 (Let's Encrypt).
inline const char* rootCA() {
  // Sectigo Public Server Authentication Root R46 (cadena de mempool.space).
  return
      "-----BEGIN CERTIFICATE-----\n"
      "MIIGlTCCBH2gAwIBAgIRANJ/u8HeNZ5SFq1hSVhgmcQwDQYJKoZIhvcNAQEMBQAw\n"
      "gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtK\n"
      "ZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYD\n"
      "VQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIx\n"
      "MDMyMjAwMDAwMFoXDTM4MDExODIzNTk1OVowXzELMAkGA1UEBhMCR0IxGDAWBgNV\n"
      "BAoTD1NlY3RpZ28gTGltaXRlZDE2MDQGA1UEAxMtU2VjdGlnbyBQdWJsaWMgU2Vy\n"
      "dmVyIEF1dGhlbnRpY2F0aW9uIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOC\n"
      "Ag8AMIICCgKCAgEAk77VNlJ12AEjoBxHQknuY7a3If3EldVIKyZ8FFMQ2nn9K7ct\n"
      "pNQs+uoy3UnCub0PSD17WphUr55dMXRPB/xQId2kz2hPGxJjbSWZTCqZ80gwYfqB\n"
      "fB6nCErcPiscHxhMcao1jK34bug7StnllALWiYQTqm3ITzPMUJY3kjPcX4jnn1TZ\n"
      "SPCYQ9Zm/Z8XOEPFAVEL1+MjDxRdWxTnS77d9MjaAzfR1jmhIVEwg7Bt1zBOlluR\n"
      "8HAkq79FgWRDDb0hOi886Z4NyyC1QifM2m+b7mQwkDnNk2WBITG1I1AzNyLjOO34\n"
      "MTDMRf5i+dFdMnlCh99qzFYZQE3Oqrv5tXZJlPEn+JGlg+UGs2MOgNzgElWApjtm\n"
      "tDmHLcjw0NEU6eQNTQ72XVdyxTscR1ad4tX7gWGMzE2AkDRbt9cUddzYBEifwMEo\n"
      "iLTpHMqnsfFWt3tJTFnlIBWohAIp+jiUaZpJBo/NH3kUFxIMg3reH7GX7vmXeCik\n"
      "yESS6X0mBaZYcpt5E9gRX67FOGI0aLKGMI74kGGeMmz1BzbNokxu7Io27fLmmRVE\n"
      "cMN8vJw5wLTha/eDJSNX2RKA5UnwdQ/vjescm1QotCE8/HwK/+97a3X/ix2gGQWr\n"
      "+vgrgULoOLq7+6r9PeDzyt9Ol5cp7fMYVumllqy9w5CYsuD5otSmR0N8bc8CAwEA\n"
      "AaOCASAwggEcMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1Ud\n"
      "DgQWBBRWc1hklfmSGrASKgRieaFAFYghSTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0T\n"
      "AQH/BAUwAwEB/zAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEQYDVR0g\n"
      "BAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRy\n"
      "dXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDA1\n"
      "BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVz\n"
      "dC5jb20wDQYJKoZIhvcNAQEMBQADggIBADpvBIlq7bMU0cFDT/9P9+BsgCkRgQs0\n"
      "S6Bf7vJSlWMHwby0VGvxCS0hrbi0K2BINZbEbsVsgpQq04431yyoVn3Hldorgq24\n"
      "RldRDOOipEZDTFB9wC9HYt1thHF00XeG2C8KC1plwoEzKAIhPvefI/C3cT0CfTXJ\n"
      "uFjUbKIgSwjNjw6YHtLgoy/hd5+JLUlLco/gzFX/qWbT7tEquOMYpsNKWZj8TLqP\n"
      "q6zMiG4Na6feEZte6YPXGrMWlTWN341vDedc+yxQqSug79HJUQcOZs7KyDWztmae\n"
      "QxsPE49UV/8XwrfZtZaYyrs4FpD94Z4Q8dzXGL8+qEJjxgcza7W6PROaClubavd1\n"
      "VKPm8+aCW77u7SxpR2TFGL6kPdxsKyFijpcunR5V79sUyROfNdzjrAcFWZXK8sbb\n"
      "9FlnwuVG677JLv+ZVTX5AxLvW5OB4zt5uS+zB62wJ/Wv+jXGAttSAcJec4iFgCWH\n"
      "Rvdi/jJoSzRLa3nEzx6pFIzclSCnh0u1xCeLcUBypSiPga8W+6PkuoyQq8U9qs9E\n"
      "oxG5NvrvlyshwUS9yvcZRGw7Ljlx4jJH/BhIPR8kIBCQj1vna9TziZOrw1Of8hDU\n"
      "bHKFG9Pm8Dp2vbjz/2JH39qvxshPKVllGfq+5klPm7yZRUYTiCMAbqwNdL/nsqF2\n"
      "Rnnyp58XRStJ\n"
      "-----END CERTIFICATE-----\n";
}

// Extrae el valor numerico que sigue a la clave JSON "key" (p.ej. "funded_txo_sum":123).
// Devuelve -1 si no encuentra la clave o el numero no es valido.
inline int64_t extractField(const String& s, const char* key) {
  int idx = s.indexOf(key);
  if (idx < 0) return -1;
  idx += static_cast<int>(strlen(key));
  const int len = s.length();
  while (idx < len && (s[idx] == ' ' || s[idx] == '\t')) ++idx;
  if (idx >= len) return -1;
  bool neg = false;
  if (s[idx] == '-') { neg = true; ++idx; }
  if (idx >= len || !isdigit(s[idx])) return -1;
  int64_t val = 0;
  while (idx < len && isdigit(s[idx])) {
    val = val * 10 + (s[idx] - '0');
    ++idx;
  }
  return neg ? -val : val;
}

// Consulta el saldo confirmado (sats) de una direccion.
// Devuelve >= 0 en exito, -1 en error de red/parseo.
// Si txCount != nullptr, guarda ahi el numero de transacciones (0 si nunca usada).
inline int64_t addressBalance(WiFiClientSecure& client, const String& address,
                              uint32_t* txCount = nullptr) {
  if (txCount) *txCount = 0;
  HTTPClient http;
  http.setTimeout(15000);
  const String url = "https://mempool.space/api/address/" + address;
  if (!http.begin(client, url)) return -1;
  const int code = http.GET();
  if (code == 404) { http.end(); return 0; }  // direccion nunca usada
  if (code != 200) { http.end(); return -1; }
  const String body = http.getString();
  http.end();
  const int64_t funded = extractField(body, "\"funded_txo_sum\":");
  const int64_t spent = extractField(body, "\"spent_txo_sum\":");
  if (funded < 0 || spent < 0) return -1;
  const int64_t tx = extractField(body, "\"tx_count\":");
  if (txCount && tx >= 0) *txCount = static_cast<uint32_t>(tx);
  return funded - spent;
}

}  // namespace mempool_balance
