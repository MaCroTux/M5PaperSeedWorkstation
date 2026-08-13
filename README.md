# M5Paper Seed Workstation

**v1.0**

Estación de trabajo offline para semillas BIP39, derivación de claves/direcciones
Bitcoin y **firma de transacciones PSBT**, ejecutada sobre un **M5Paper** (ESP32
con pantalla e-paper de 540×960 y táctil GT911).

> **AVISO**: los datos son de prueba. **NO USAR CON FONDOS REALES** hasta completar
> una revisión de seguridad formal.

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
- **Recibir PSBT por WiFi** (punto de acceso + portal cautivo) o por **serial USB**.
- **Firmar PSBT** (segwit P2WPKH, ECDSA RFC6979 + BIP143) y emitir la transacción:
  - **Sparrow**: QR estático (hex de la transacción firmada).
  - **BlueWallet**: QR animado **BBQr** (PSBT en Base64 para payload pequeño,
    multipart `B$HPxxxx` para payload grande).
- Auto-bloqueo de la sesión por inactividad y **bloqueo manual** con portada.

---

## 2. Menú principal

```
INTRODUCIR SEMILLA      (escribe una semilla BIP39)
GENERAR ENTROPIA        (dibuja o tira dados)
VAULT DE SESION         (crear/abrir vault de varias semillas)
AYUDA                   (glosario de conceptos)
RECIBIR POR WIFI        (AP para recibir PSBT desde el móvil)
BLOQUEAR                (borra semilla/sesión y muestra la portada)
```

Cuando hay una semilla activa, la primera opción pasa a **SEMILLA ACTIVA** y
"GENERAR ENTROPIA" se deshabilita. "RECIBIR POR WIFI" solo se activa con semilla
cargada.

---

## 3. Flujo de firma (PSBT)

```
PSBT (WiFi o serial)
   ↓
M5Paper decodifica y muestra la transacción
   (PAGO / CAMBIO / COMISIÓN + direcciones en recuadro)
   ↓
[ DETALLE ] → lista de UTXOs (entradas)
   ↓
[ FIRMAR ]  → firma cada entrada (segwit P2WPKH)
   ↓
[ EMITIR ]  → SPARROW (QR estático hex)  |  BLUEWALLET (QR BBQr)
   ↓
Wallet externa reconoce y emite la transacción
```

Verificado de extremo a extremo: BlueWallet lee la transacción firmada y el
resultado coincide con Coinb.in.

---

## 4. Recibir PSBT

### Por WiFi

1. **SEMILLA ACTIVA → RECIBIR POR WIFI** (o menú principal).
2. El M5Paper crea un AP `M5Paper-QR` (clave aleatoria) con **QR de conexión** y
   **portal cautivo**.
3. El móvil escanea el QR, se conecta, y la web se abre sola.
4. Sube el fichero `.psbt` o pega el contenido.

### Por serial (desarrollo)

```bash
python3 PSBTSerialSend.py archivo.psbt
```

Protocolo: `M5PSBT <len> <sha256>\n` + payload binario + `\nM5END\n`.
El M5Paper responde `READY` y verifica el SHA256 antes de procesar.

También acepta `incommit-transaction: <base64>` como comando de texto.

---

## 5. Arquitectura de ficheros

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
| `psbt_parser.hpp` | Parser de PSBT (BIP174) y transacciones, detección binario/base64/hex. |
| `tx_sign.hpp` | Firma segwit: RFC6979, sighash BIP143, finalización y serialización. |
| `bbqr.hpp` | Codificación BBQr (BIP-129 / Coinkite): cabecera `B$HPxxxx` + hex. |
| `seedqr_qrcode.c/.h` | Generación de QR (licencia MIT). |
| `generated/bip39_english.h` | Las 2048 palabras en PROGMEM. |
| `qr_wifi_server.hpp` | Punto de acceso WiFi + servidor HTTP + portal cautivo. |
| `qr_ble_client.hpp/.cpp` | Cliente BLE (NimBLE) — **oculto en el menú, no eliminado**. |
| `AUDITORIA.md` | Auditoría de seguridad y UX. |

---

## 6. Compilación

### PlatformIO (validación de compilación)

```bash
~/.platformio/penv/bin/pio run -e native
```

El entorno `native` usa `espressif32@5.0.0` (core arduino-esp32 **2.0.3**),
placa `m5stack-fire`, librería `M5EPD` desde `~/Documents/Arduino/libraries/M5EPD`
y `NimBLE-Arduino@^1.4.0`.

### Arduino IDE (build real / flasheo)

- Tarjeta: **M5Stack-FIRE**, core **esp32 2.0.3**.
- Librerías en `~/Documents/Arduino/libraries`: `M5EPD`, `NimBLE-Arduino` (v1.4.x).

Flasheo fiable en USB marginal: `esptool.py --no-stub --baud 115200 write_flash 0x10000 firmware.bin`.

---

## 7. Diseño de seguridad

- **Cifrado en reposo**: AES-256-GCM con cabecera completa como AAD; detecta
  manipulación de sal, nonce y metadatos.
- **Derivación de clave**: PBKDF2-HMAC-SHA256 con **600.000 iteraciones** y sal de
  16 bytes aleatoria por archivo (RNG de hardware `esp_fill_random`).
- **Firma**: ECDSA secp256k1 con **nonce determinista RFC6979** + **low-S**; sighash
  **BIP143** (segwit v0). Verificación de la ruta BIP32 por fingerprint maestra.
- **Limpieza de memoria**: funciones `wipe()` (volátil) sobre claves, plaintext,
  buffers de semilla, etc.
- **Auto-bloqueo de sesión** (3 min) y bloqueo manual.
- **Self-tests al arranque**: BIP39, BIP32, fingerprint, PBKDF2 (contra
  `mbedtls_pkcs5_pbkdf2_hmac`), ECDSA (RFC6979), PSBT parser, direcciones BIP84/BIP86.

---

## 8. Bluetooth (oculto, no eliminado)

Cliente BLE (`qr_ble_client.hpp/.cpp`) para recibir QR desde una Raspberry Pi
(servidor GATT `M5Paper-QR`), **desactivado** en el menú (la entrada apunta a WiFi).
Se pasó de Bluedroid a **NimBLE** porque Bluedroid producía `configASSERT` internos
(`BTA_GATTC_Open` → `prvCopyDataToQueue`) en el M5Paper.

---

## 9. Estado / pendientes

- [x] Auditoría de seguridad y UX (`AUDITORIA.md`).
- [x] Mejoras de navegación y UX.
- [x] Recepción por WiFi AP (portal cautivo + QR de conexión).
- [x] Recepción por serial USB (protocolo `M5PSBT` + SHA256).
- [x] Parsing de PSBT (BIP174) y desglose PAGO/CAMBIO/COMISIÓN.
- [x] Firma de PSBT (segwit P2WPKH) + salida QR estático (Sparrow) y BBQr (BlueWallet).
- [ ] Corregir el self-test **BIP86** (falla; BIP84 OK).
- [ ] Consolidar la UI legacy (`.ino`) en `NativeApp.cpp`.
- [ ] Base32 y zlib en BBQr (optimización futura).

---

## 10. Advertencia de uso

Este firmware gestiona claves privadas. No usar con fondos reales hasta completar
una revisión de seguridad formal y pruebas físicas exhaustivas.
