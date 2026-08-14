# M5Paper Seed Workstation

**v1.2**

Estación de trabajo offline para semillas BIP39, derivación de claves/direcciones
Bitcoin y **firma de transacciones PSBT**, ejecutada sobre un **M5Paper** (ESP32
con pantalla e-paper de 540×960 y táctil GT911).

> **AVISO**: los datos son de prueba. **NO USAR CON FONDOS REALES** hasta completar
> una revisión de seguridad formal.

> **Nota**: este proyecto se ha creado en **Vibe Coding**, como **experimento**.
> No lo uses con fondos reales.

Documentación en inglés: [`README.md`](README.md).

---

## 1. Qué hace

- **Introducir semilla BIP39** (teclado con autocompletado de las 2048 palabras).
- **Generar entropía** dibujando en pantalla o lanzando dados.
- **Revisión y backup** de la semilla: palabras, QR y **SEEDQR** (asistente offline).
- **Clave pública**: derivar y mostrar xpub/zpub (BIP32), con QR.
- **Explorador de direcciones**: derivar direcciones P2PKH, P2SH y native segwit
  (BIP84), para recepción y cambio, con salto directo a un índice.
- **Passphrase BIP39** (cambia todas las direcciones derivadas).
- **Vault individual**: una semilla cifrada con su propia contraseña (archivo `.vlt`).
- **Vault de sesión**: varias semillas cifradas bajo una contraseña maestra.
- **Llave BLE (M5Core2)**: llave criptográfica física que desbloquea el vault de
  sesión mediante **challenge/response** BLE + un **PIN** de 6 dígitos. La llave se
  empareja por Bluetooth con ECDH (sin teclear nada); un vault existente solo con
  contraseña se puede **migrar** a "contraseña + llave".
- **Recibir por WiFi** (punto de acceso + portal cautivo) o por **serial USB**:
  PSBT (fichero o texto) o semilla BIP39 en texto (esta última sin necesidad de
  tener una semilla cargada en RAM).
- **Firmar PSBT** (ECDSA RFC6979 + BIP143) y emitir la transacción:
  - **Single-sig** P2WPKH.
  - **Multisig** P2WSH `sortedmulti` (BIP48), 2-de-2 / 2-de-3 / 3-de-3, con
    interoperabilidad Sparrow; firma con todas las seeds del Vault en un solo paso.
  - **Sparrow**: QR estático (hex de la transacción firmada).
  - **BlueWallet**: QR animado **BBQr** (solo single-sig).
- **Historial de transacciones**: cada PSBT recibida se guarda en la SD y se puede
  revisar y volver a firmar más tarde.
- **Ajustes** guardados en la SD: idioma (inglés por defecto / español),
  tiempo de bloqueo automático (1/3/5/10 min o nunca), tiempo de limpieza de seed
  (nunca/10/30/60 min), derivación por defecto (BIP44/49/84) y estado de la
  radio (BT/WiFi/energía).
- **Bloqueo** manual o por inactividad con **portada estática** (sin animaciones,
  para no consumir batería en e-ink) que sirve también como pantalla de apagado.

---

## 2. Menú principal

```
INTRODUCIR SEMILLA      (escribe una semilla BIP39)
GENERAR ENTROPIA        (dibuja o tira dados)
VAULT DE SESION         (crear/abrir vault de varias semillas)
RECIBIR POR WIFI        (AP para recibir PSBT o semilla desde el móvil)
HISTORIAL               (transacciones guardadas para revisar o volver a firmar)
AJUSTES                 (idioma, bloqueo, derivación, radio)
BLOQUEAR                (bloquea el dispositivo con la portada)
```

La **ayuda** está disponible como icono `?` en la esquina inferior derecha del
menú principal (opción secundaria).

Cuando hay una semilla activa, la primera opción pasa a **SEMILLA ACTIVA** y
"GENERAR ENTROPIA" se deshabilita.

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

## 4. Recibir PSBT / semilla

### Por WiFi

1. **RECIBIR POR WIFI** (menú principal o menú de semilla activa).
2. Elige el modo de entrada:
   - **SUBIR FICHERO (PSBT)**: sube un fichero `.psbt` (requiere semilla cargada).
   - **PEGAR TRANSACCION (PSBT)**: pega el PSBT en texto (base64, hex o UR) (requiere semilla cargada).
   - **PEGAR SEMILLA BIP39**: importa una semilla de 12/24 palabras (no requiere semilla previa).
3. El M5Paper crea un AP `M5Paper-QR` (clave aleatoria) con **QR de conexión** y
   **portal cautivo** adaptado al modo elegido.
4. El móvil escanea el QR, se conecta, y la web se abre sola.
5. Sube/pega el contenido. El AP se apaga automáticamente al recibirlo.

### Por serial (desarrollo)

```bash
python3 PSBTSerialSend.py archivo.psbt
```

Protocolo: `M5PSBT <len> <sha256>\n` + payload binario + `\nM5END\n`.
El M5Paper responde `READY` y verifica el SHA256 antes de procesar.

También acepta `incommit-transaction: <base64>` como comando de texto.

### Protocolo de consola (por líneas)

La consola de escritorio (`m5paper_console.py`) puede controlar el dispositivo por
serial con comandos ASCII por línea (cada uno acaba en `\n`):

| Comando | Respuesta |
|---|---|
| `M5PING` | `M5OK version=<ver>` |
| `M5TIME <unix>` | `M5OK time=<unix>` (pone en hora el RTC) |
| `M5VAULT LIST` | `M5VAULTS N` + `VLT/SVM\t<fichero>\t<etiqueta>` … `M5END` |
| `M5VAULT SEEDS <nombre>` | `M5SEEDS N` + `<fpr>\t<etiqueta>` … `M5END` |
| `M5VAULT OPEN <nombre>` | `READY` (luego espera `M5PASS`) |
| `M5PASS <contraseña>` | `M5OK vault=… [fingerprint=… words=… | seeds=…]` |
| `M5SEED <palabras>` | `M5OK fingerprint=<fpr> words=<n>` |
| `M5TX LIST` | `M5TXS N` + `PSBT\t<fichero>` … `M5END` |
| `M5TX LOAD <nombre>` | `M5OK tx=… inputs=… outputs=… [fee/pago/cambio/multisig]` |
| `M5TX SIGN` | `M5OK signed=tx hex=…` / `M5OK signed=partial …` |
| `M5STATE` | `M5OK fingerprint=… words=… tx=…` |

Los errores se reportan como `M5ERR <código>` (`no_sd`, `io_error`,
`wrong_password`, `locked`, `invalid_seed`, `invalid`, `not_found`, `bad_cmd`).

**Invariante de seguridad**: la semilla (palabras/índices) y la clave privada
**nunca** salen por serial. Solo salen el fingerprint (4 bytes), las firmas, las
transacciones firmadas, los resúmenes y la metadata en claro de la SD.

---

## 5. Arquitectura de ficheros

| Fichero | Rol |
|---|---|
| `NativeApp.cpp` | UI principal (M5EPD): pantallas, navegación, máquina de estados. |
| `M5PaperSeedWorkstation.ino` | Punto de entrada del sketch (la UI vive en `NativeApp.cpp`). |
| `bip39_support.hpp` | Lista BIP39, búsqueda por prefijo, checksum, `from_entropy`, self-tests. |
| `bitcoin_hd.hpp` | BIP32: BIP39→seed, derivación endurecida/normal, xpub/zpub, base58check. |
| `bitcoin_address.hpp` | Direcciones P2PKH/P2SH/native segwit/taproot (bech32, bech32m). |
| `bitcoin_fingerprint.hpp` | Fingerprint de la clave maestra. |
| `ripemd160_min.hpp` | RIPEMD-160. |
| `encrypted_seed_store.hpp` | Vault individual: AES-256-GCM + PBKDF2. |
| `session_vault_store.hpp` | Vault de sesión: clave maestra + semillas. |
| `ble_key.hpp` | Cripto compartida de la llave BLE (HMAC-SHA256, ECDH secp256k1, NVS). |
| `ble_key_client.hpp/.cpp` | Cliente BLE (M5Paper): scan → challenge → verificar HMAC + emparejamiento. |
| `ble_key_server.hpp/.cpp` | Servidor GATT BLE (M5Core2): challenge/response + emparejamiento (ALLOW/DENY). |
| `vault_key.hpp` | Segundo factor Core2+PIN: envuelve la clave maestra de sesión (`.k2f`). |
| `psbt_parser.hpp` | Parser de PSBT (BIP174) y transacciones, detección binario/base64/hex/UR. |
| `ur_psbt.hpp` | Decodificación de `UR:CRYPTO-PSBT` (bytewords + CBOR). |
| `tx_sign.hpp` | Firma segwit: RFC6979, sighash BIP143, finalización y serialización. |
| `bbqr.hpp` | Codificación BBQr (BIP-129 / Coinkite): cabecera `B$HPxxxx` + hex. |
| `seedqr_qrcode.c/.h` | Generación de QR (licencia MIT). |
| `generated/bip39_english.h` | Las 2048 palabras en PROGMEM. |
| `qr_wifi_server.hpp` | Punto de acceso WiFi + servidor HTTP + portal cautivo. |
| `qr_ble_client.hpp/.cpp` | Cliente BLE (NimBLE) — **oculto en el menú, no eliminado**. |
| `lang.hpp` | Traducción EN/ES (`lang::tr`), con tabla castellano→inglés. |
| `device_settings.hpp` | Ajustes persistentes en SD (`/m5settings.cfg`): idioma, bloqueo, derivación. |
| `AUDITORIA.md` | Auditoría de seguridad y UX. |
| `TECHNICAL.md` | Documentación técnica detallada. |
| `DEBUG_FIRMA.md` | Post-mortem del bug de firma P2WPKH. |

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
- **Llave BLE (Core2 + PIN)**: la clave maestra del vault de sesión se envuelve
  además bajo `K_2f = HMAC-SHA256(K_pair, PBKDF2(PIN))`, donde `K_pair` es un
  secreto de 256 bits establecido por ECDH durante el emparejamiento. La ruta por
  contraseña sigue siempre disponible como recuperación.
- **Firma**: ECDSA secp256k1 con **nonce determinista RFC6979** + **low-S**; sighash
  **BIP143** (segwit v0). Verificación de la ruta BIP32 por fingerprint maestra.
- **Limpieza de memoria**: funciones `wipe()` (volátil) sobre claves, plaintext,
  buffers de semilla, etc.
- **Auto-bloqueo** por inactividad (configurable) y bloqueo manual.
- **Self-tests al arranque**: BIP39, BIP32, fingerprint, PBKDF2 (contra
  `mbedtls_pkcs5_pbkdf2_hmac`), ECDSA (RFC6979), PSBT parser, direcciones BIP84.

---

## 8. Bluetooth (oculto, no eliminado)

Cliente BLE (`qr_ble_client.hpp/.cpp`) para recibir QR desde una Raspberry Pi
(servidor GATT `M5Paper-QR`), **desactivado** en el menú. Se pasó de Bluedroid a
**NimBLE** porque Bluedroid producía `configASSERT` internos en el M5Paper.

---

## 9. Llave BLE (M5Core2): contraseña + llave

Un **M5Core2** actúa como llave criptográfica física que desbloquea el **vault de
sesión** (`.svm`), como segundo factor junto a un PIN de 6 dígitos.

### Emparejamiento (una vez, sin teclear)

1. Core2: menú → `LLAVE BLE` (genera su identidad la primera vez).
2. M5Paper: `AJUSTES → BLE KEY → EMPAREJAR M5CORE2`.
3. El Core2 muestra `PAIR REQUEST` → pulsa `AUTHORIZE`.
4. Ambos derivan el secreto compartido `K_pair` mediante **ECDH sobre secp256k1**;
   nunca viaja por el aire.

### Activar / migrar un vault

- Vault nuevo: desbloquea por contraseña → `ACTIVAR CORE2+PIN` (menú de sesión).
- Vault existente solo con contraseña: `AJUSTES → BLE KEY → MIGRAR A PASS+LLAVE` →
  elige el `.svm` → introduce su contraseña → define el PIN. La contraseña sigue
  disponible como recuperación.

### Desbloquear

`VAULT DE SESION → DESBLOQUEAR CON CORE2` → el M5Paper verifica el Core2 con un
challenge/response nuevo → introduce el PIN → el vault se abre. El Core2 nunca ve
la clave maestra, el PIN ni las semillas.

---

## 10. Estado / pendientes

- [x] Recepción por WiFi AP (portal cautivo + QR de conexión) con 3 modos.
- [x] Recepción por serial USB (protocolo `M5PSBT` + SHA256).
- [x] Decodificación de PSBT `UR:CRYPTO-PSBT` (QR de Sparrow).
- [x] Firma de PSBT (single-sig P2WPKH + multisig P2WSH sortedmulti) + QR (Sparrow/BlueWallet).
- [x] Ajustes persistentes en SD (idioma, bloqueo, derivación, radio).
- [x] Historial de transacciones (guardar y volver a firmar PSBT recibidas).
- [x] Traducción completa EN/ES.
- [x] Llave BLE (M5Core2) + PIN como segundo método de desbloqueo del vault de sesión.
- [ ] Base32 y zlib en BBQr (optimización futura).

---

## 11. Advertencia de uso

Este firmware gestiona claves privadas. No usar con fondos reales hasta completar
una revisión de seguridad formal y pruebas físicas exhaustivas.
