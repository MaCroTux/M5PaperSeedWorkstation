# M5Paper Seed Workstation

Estación de trabajo offline para semillas BIP39 y derivación de claves/direcciones
Bitcoin, ejecutada sobre un **M5Paper** (ESP32 con pantalla e-paper de 540×960 y
táctil GT911).

> **AVISO**: proyecto en desarrollo. Los datos son de prueba. **NO USAR CON FONDOS REALES.**

---

## 1. Qué hace

- **Introducir semilla BIP39** (teclado con autocompletado de las 2048 palabras).
- **Generar entropía** dibujando en pantalla o lanzando dados.
- **Revisión y backup** de la semilla: palabras, QR y **SEEDQR** (asistente offline).
- **Clave pública**: derivar y mostrar xpub/zpub (BIP32), con QR.
- **Explorador de direcciones**: derivar direcciones P2PKH, P2SH, native segwit
  (BIP84) y taproot (BIP86), para recepción y cambio, con salto directo a un índice.
- **Passphrase BIP39** (cambia todas las direcciones derivadas).
- **Vault individual**: una semilla cifrada con su propia contraseña (archivo `.vlt`).
- **Vault de sesión**: varias semillas cifradas bajo una contraseña maestra.
- **Recibir datos por WiFi** (punto de acceso): subir un archivo o pegar contenido
  de QR desde el móvil.
- Auto-bloqueo de la sesión por inactividad.

---

## 2. Menú principal

```
INTRODUCIR SEMILLA      (escribe una semilla BIP39)
GENERAR ENTROPIA        (dibuja o tira dados)
VAULT DE SESION         (crear/abrir vault de varias semillas)
AYUDA                   (glosario de conceptos)
RECIBIR POR WIFI        (AP para recibir archivo/contenido desde el móvil)
```

Cuando hay una semilla activa, la primera opción pasa a **SEMILLA ACTIVA** y la
generación de entropía se deshabilita hasta descartarla.

---

## 3. Arquitectura de ficheros

| Fichero | Rol |
|---|---|
| `NativeApp.cpp` | UI principal (M5EPD): pantallas, navegación, máquina de estados. |
| `M5PaperSeedWorkstation.ino` | UI legacy (M5GFX), inactiva (guarda `LEGACY_M5GFX_BUILD`). |
| `bip39_support.hpp` | Lista BIP39, búsqueda por prefijo, checksum, `from_entropy`, self-tests. |
| `bitcoin_hd.hpp` | BIP32: BIP39→seed, derivación endurecida/normal, xpub/zpub, base58check. |
| `bitcoin_address.hpp` | Direcciones P2PKH/P2SH/native segwit/taproot (bech32, bech32m). |
| `bitcoin_fingerprint.hpp` | Fingerprint de la clave maestra. |
| `ripemd160_min.hpp` | RIPEMD-160. |
| `encrypted_seed_store.hpp` | Vault individual: AES-256-GCM + PBKDF2. |
| `session_vault_store.hpp` | Vault de sesión: clave maestra + semillas. |
| `seedqr_qrcode.c/.h` | Generación de QR (licencia MIT). |
| `generated/bip39_english.h` | Las 2048 palabras en PROGMEM. |
| `qr_wifi_server.hpp` | Punto de acceso WiFi + servidor HTTP para recibir contenido. |
| `qr_ble_client.hpp/.cpp` | Cliente BLE (NimBLE) — **oculto en el menú, no eliminado**. |
| `AUDITORIA.md` | Auditoría de seguridad y UX. |

---

## 4. Compilación

### PlatformIO (validación de compilación)

```bash
~/.platformio/penv/bin/pio run -e native
```

El entorno `native` usa `espressif32@5.0.0` (core arduino-esp32 **2.0.3**),
placa `m5stack-fire`, librería `M5EPD` desde `~/Documents/Arduino/libraries/M5EPD`
y `NimBLE-Arduino@^1.4.0`.

### Arduino IDE (build real / flasheo)

- Tarjeta: **M5Stack-FIRE**, core **esp32 2.0.3**.
- Librerías instaladas en `~/Documents/Arduino/libraries`:
  - `M5EPD`
  - `NimBLE-Arduino` (v1.4.x, autor h2zero)

---

## 5. Diseño de seguridad

- **Cifrado en reposo**: AES-256-GCM con cabecera completa como *additional
  authenticated data* (AAD); detecta manipulación de sal, nonce y metadatos.
- **Derivación de clave**: PBKDF2-HMAC-SHA256 con **600.000 iteraciones** y sal de
  16 bytes aleatoria por archivo (RNG de hardware `esp_fill_random`).
- **Integridad en transporte BLE**: reconstrucción de chunks por índice +
  verificación `SIZE` y `SHA256` del payload.
- **Limpieza de memoria**: funciones `wipe()` (volátil) sobre claves, plaintext,
  buffers de semilla, etc.
- **Auto-bloqueo de sesión**: a los 3 minutos sin actividad, con aviso previo.
- **Self-tests al arranque**: BIP39, BIP32, fingerprint, PBKDF2 (contra
  `mbedtls_pkcs5_pbkdf2_hmac`), direcciones BIP84/BIP86.

---

## 6. Recibir por WiFi (MVP)

1. En el menú → **RECIBIR POR WIFI**. El M5Paper crea un punto de acceso con una
   **clave aleatoria por sesión** y muestra un **QR de conexión** en pantalla
   (`WIFI:T:WPA;S:M5Paper-QR;P:<clave>;;`).
2. El móvil escanea el QR y se conecta automáticamente a la red `M5Paper-QR`.
3. Abre `http://192.168.4.1` en el navegador y **pega el contenido** de un QR o
   **sube un archivo** (p. ej. un PSBT).
4. El M5Paper muestra el contenido recibido (texto o "binary payload N bytes") y
   **apaga el AP automáticamente**.

El contenido llega como payload crudo (`format`/`type` + bytes). La integridad la
garantiza TCP; la interpretación del contenido (PSBT, etc.) se hará en una fase
posterior.

---

## 7. Bluetooth (oculto, no eliminado)

Existe un cliente BLE completo (`qr_ble_client.hpp/.cpp`) pensado para recibir un QR
decodificado por una Raspberry Pi (servidor GATT `M5Paper-QR`). Está **desactivado**
en el menú (la entrada apunta a WiFi). Para reactivarlo basta con volver a conectar
la entrada del menú a `beginScanQr()`.

Nota técnica: la implementación pasó de Bluedroid a **NimBLE** porque Bluedroid
producía un `configASSERT` interno (`BTA_GATTC_Open` → `prvCopyDataToQueue`) en el
M5Paper; NimBLE es más ligero y no usa esa arquitectura.

---

## 8. Estado / pendientes

- [x] Auditoría de seguridad y UX (`AUDITORIA.md`).
- [x] Mejoras de navegación y UX (barra de progreso, entrada numérica de índice,
      aviso de auto-bloqueo, ayuda contextual, toast, etc.).
- [x] Recepción por WiFi AP (MVP).
- [x] QR de conexión WiFi con clave aleatoria + apagado automático del AP.
- [ ] Verificar en hardware la recepción WiFi y el BLE/NimBLE.
- [ ] Parsing/interpretación de PSBT.
- [ ] Corregir el self-test **BIP86** (falla; BIP84 OK).
- [ ] Consolidar la UI legacy (`.ino`) en `NativeApp.cpp`.

---

## 9. Advertencia de uso

Este firmware gestiona claves privadas. No usar con fondos reales hasta completar
una revisión de seguridad formal y pruebas físicas exhaustivas.
