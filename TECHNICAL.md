# Documentación técnica — M5Paper Seed Workstation

**Versión 1.1** · Licencia **GPL-3.0-or-later**

> **Aviso importante**: este proyecto se ha desarrollado con **Vibe Coding** como
> **experimento**. El código no ha pasado una auditoría de seguridad formal y **no
> debe usarse con fondos reales**. Consulta [`AUDITORIA.md`](AUDITORIA.md) para los
> hallazgos conocidos.

---

## 1. Contexto y objetivos

M5Paper Seed Workstation es un firmware para el **M5Paper** (módulo ESP32 con
pantalla e-paper de 540×960, táctil GT911 y ranura microSD) que actúa como
**billetera offline / dispositivo de firma**:

- Gestiona **semillas BIP39** (entrada, entropía, revisión, backup, cifrado).
- Deriva **claves públicas extendidas** (xpub/ypub/zpub) y **direcciones** Bitcoin.
- Recibe **PSBT** por WiFi o serial, los muestra y los **firma** (segwit P2WPKH).
- Emite la transacción firmada como **QR** para wallets de escritorio/móvil.

Todo el material sensible se genera, procesa y firma **sin conexión**; la radio
WiFi solo se enciende bajo demanda para recibir un PSBT o una semilla, y el BLE
permanece oculto.

---

## 2. Hardware y toolchain

| Componente | Detalle |
|---|---|
| Placa | **M5Paper** (ESP32-PICO-D4, 4 MB PSRAM, 16 MB flash) |
| Pantalla | e-paper 4,7" 540×960 (controlador IT8951 vía `M5EPD`) |
| Táctil | GT911 |
| microSD | para vaults cifrados y ajustes |
| Framework | Arduino (core **arduino-esp32 2.0.3**) |
| Librerías | `M5EPD`, `NimBLE-Arduino@^1.4.0` |
| Compilación | PlatformIO (`platformio.ini`, env `native`, board `m5stack-fire`) |

Build de validación:

```bash
~/.platformio/penv/bin/pio run -e native
```

Flasheo fiable sobre USB marginal:

```bash
esptool.py --chip esp32 --port /dev/cu.usbserial-XXX --baud 115200 --no-stub \
  write_flash 0x10000 .pio/build/native/firmware.bin
```

---

## 3. Arquitectura de ficheros

| Fichero | Responsabilidad |
|---|---|
| `NativeApp.cpp` | UI completa (M5EPD): pantallas, navegación, máquina de estados, i18n, ajustes, firma, BBQr. |
| `M5PaperSeedWorkstation.ino` | Punto de entrada del sketch (solo `setup`/`loop` delegados). |
| `bip39_support.hpp` | Lista BIP39 (2048 palabras en PROGMEM), `find_exact`/`find_matches`, `checksum_valid`, `from_entropy`, self-test. |
| `bitcoin_hd.hpp` | BIP32: `mnemonic_seed` (PBKDF2-HMAC-SHA512 2048 iter.), derivación endurecida/normal, xpub/zpub, base58check. |
| `bitcoin_address.hpp` | Direcciones P2PKH/P2SH/native segwit (BIP84), bech32/bech32m. |
| `bitcoin_fingerprint.hpp` | Fingerprint de clave maestra (BIP32). |
| `ripemd160_min.hpp` | RIPEMD-160 (para HASH160). |
| `encrypted_seed_store.hpp` | Vault individual (`.vlt`): AES-256-GCM + PBKDF2 (600.000 iter.). |
| `session_vault_store.hpp` | Vault de sesión: clave maestra + semillas cifradas (`.svm`/`.svs`). |
| `ble_key.hpp` | Cripto compartida de la llave BLE: HMAC-SHA256, ECDH secp256k1, persistencia NVS. |
| `ble_key_client.hpp/.cpp` | Cliente BLE (M5Paper): emparejamiento ECDH + challenge/response HMAC. |
| `ble_key_server.hpp/.cpp` | Servidor GATT BLE (M5Core2): challenge/response + emparejamiento con confirmación física. |
| `vault_key.hpp` | Segundo factor Core2+PIN: envuelve la clave maestra de sesión (`.k2f`). |
| `psbt_parser.hpp` | Parser PSBT (BIP174) + deserialización de transacciones; detecta binario/base64/hex/UR. |
| `ur_psbt.hpp` | Decodificación `UR:CRYPTO-PSBT` (bytewords + CBOR) para QR de Sparrow. |
| `tx_sign.hpp` | Firma segwit v0: RFC6979, sighash BIP143, finalización PSBT, serialización. |
| `bbqr.hpp` | Codificación **BBQr** (BIP-129): cabecera `B$HPxxxx` + hex, multipart. |
| `seedqr_qrcode.c/.h` | Generación de QR (MIT). |
| `qr_wifi_server.hpp` | AP WiFi + servidor HTTP (WebServer) + DNS (portal cautivo). |
| `qr_ble_client.hpp/.cpp` | Cliente BLE NimBLE (oculto, no eliminado). |
| `lang.hpp` | i18n EN/ES (`lang::tr`), tabla castellano→inglés. |
| `device_settings.hpp` | Ajustes en SD (`/m5settings.cfg`). |
| `multisig.hpp` | Multisig P2WSH sortedmulti (detección, firma, finalización). |
| `DEBUG_FIRMA.md` | Post-mortem del bug de firma P2WPKH (scriptCode + pubkey comprimida). |

---

## 4. Criptografía

### 4.1 Generación y manejo de la semilla

- **Entropía**: mezcla de entropía física (trazos táctiles o dados) con
  `esp_fill_random`/`bootloader_random_enable`; el material se acumula mediante
  SHA-256 y se condensa en `bip39::from_entropy` (16 B → 12 palabras, 32 B → 24).
- **Checksum BIP39**: `bip39::checksum_valid` recalcula los bits de checksum y los
  compara (detecta semillas mal copiadas).
- **Fingerprint BIP32**: `bitcoin_fingerprint::calculate` (HASH160 de la clave
  maestra) para verificar visualmente y para identificar la semilla en PSBT.

### 4.2 Derivación (BIP32/BIP39)

- `mnemonic_seed` usa **PBKDF2-HMAC-SHA512** con 2048 iteraciones (estándar BIP39).
- Derivación endurecida (`0'`, `84'`, etc.) y normal (`0`, `1`, …) con aritmética
  de mbedTLS sobre secp256k1.
- Perfiles soportados: BIP44 (P2PKH), BIP49 (P2SH-SegWit), **BIP84 (native SegWit,
  por defecto)**.

### 4.3 Vaults (cifrado en reposo)

- **PBKDF2-HMAC-SHA256 con 600.000 iteraciones**, sal aleatoria de 16 bytes por
  archivo (`esp_fill_random`).
- **AES-256-GCM** con la cabecera completa (magia, versión, iteraciones, sal,
  nonce, longitud) como **AAD**, de modo que cualquier manipulación de metadatos
  invalida el tag.
- Verificación tras guardar: se relee el archivo y se compara la semilla antes de
  darlo por bueno.
- Limpieza con `wipe()` (`volatile`) sobre claves, plaintext, buffers y tags.

### 4.4 Firma (segwit v0 / P2WPKH)

- **Nonce determinista RFC6979** (HMAC-SHA256 sobre el mensaje + clave) + **low-S**
  (BIP62).
- **Sighash BIP143** para entradas segwit v0.
- Localización de la clave: por derivación (fingerprint maestra + ruta BIP32) o
  por búsqueda de la dirección en la rama de cambio (para PSBT de BlueWallet que no
  traen ruta).
- Finalización del PSBT (se añade `final_scriptSig`/`final_scriptWitness`) y
  serialización de la transacción.

### 4.5 Self-tests al arranque

BIP39, BIP32 xpub/zpub (+ passphrase), fingerprint, PBKDF2 (comparado contra
`mbedtls_pkcs5_pbkdf2_hmac`), ECDSA/RFC6979, parser PSBT y direcciones BIP84.

### 4.6 Llave BLE (M5Core2) + PIN

La llave Core2 añade un **segundo método de desbloqueo** del vault de sesión, sin
modificar el formato `.svm`/`.svs` existente.

**Modelo asimétrico.** El Core2 guarda una clave privada `sk` (secp256k1) y expone
su clave pública `pk`. El M5Paper cifra la maestra `M` del vault con `pk`; solo el
Core2 puede descifrarla. Así, robar únicamente el M5Paper no revela nada.

**Emparejamiento.** El M5Paper lee `pk` (característica `PAIR_PUBKEY` de solo
lectura) y escribe `PAIR_CONFIRM`; el Core2 muestra `PAIR REQUEST` y, al pulsar
`AUTHORIZE`, confirma. El M5Paper guarda `pk` en NVS (`bpk`), que es pública.

**Clave protegida por PIN.** En el Core2, `sk` se guarda cifrada en NVS (`ksk`):

```
K_pin = PBKDF2-HMAC-SHA256(PIN, salt, 150.000)
ksk   = salt ‖ nonce ‖ AES-256-GCM(sk, K_pin) ‖ tag
```

El PIN se introduce en el propio Core2. 3 PINs fallidos borran `ksk` (la llave
queda inutilizada; el vault solo se recupera re-migrando con la contraseña).

**Envolver la maestra.** La maestra `M` (32 bytes) se guarda en un `.k2f`:

```
blob = E ‖ nonce ‖ AES-256-GCM(M, K_ecies) ‖ tag     (E = clave pública efímera)
K_ecies = SHA256(x(ECDH(e, pk)) ‖ tag)
```

**Desbloqueo.** El M5Paper envía `E_sess ‖ blob` al Core2 (característica
`UNLOCK_REQ`). El Core2 pide el PIN, recupera `sk`, descifra `M`, deriva la clave
de sesión `K_sess = SHA256(x(ECDH(sk, E_sess)) ‖ tag)` y devuelve
`AES-256-GCM(M, K_sess)` por `UNLOCK_RESP`. El M5Paper descifra con su `e_sess` y
`pk`. `M` nunca viaja en claro; el Core2 solo la ve en RAM durante el descifrado.

La contraseña sigue operativa como recuperación, y `MIGRAR A PASS+LLAVE` añade la
llave a un vault existente sin perder acceso.

---

## 5. QR y emisión

| Destino | Formato |
|---|---|
| **Sparrow** | QR estático con el **hex** de la transacción firmada. |
| **BlueWallet** | payload pequeño → **Base64** (`cHNidP8...`); payload grande → **BBQr** multipart (`B$HPxxxx` + hex). |

Detalles importantes aprendidos durante el desarrollo:

- La librería QR (`seedqr_qrcode.c`) **no valida capacidad**; la versión debe
  elegirse según la tabla de capacidad en **bytes** (Base64/bytes), no alfanumérica.
- BBQr usa cabecera de **8 caracteres** (`B$` + codificación + tipo + total/base36
  + índice/base36), índice en base36 empezando en 0, ECC L y zona de silencio de
  4 módulos.
- `UR:CRYPTO-PSBT` (bytewords→CBOR→PSBT) se acepta para los QR de Sparrow.

---

## 6. Comunicaciones

### 6.1 WiFi (recepción)

`qr_wifi_server.hpp` levanta un AP `M5Paper-QR` con clave aleatoria por sesión y
portal cautivo (DNS). Tres modos:

1. **Subir fichero** (PSBT) — `POST /upload`.
2. **Pegar transacción** (PSBT base64/hex/UR) — `POST /paste`.
3. **Pegar semilla** (BIP39 12/24 palabras) — `POST /paste`.

El AP se apaga automáticamente al recibir el contenido. La semilla recibida por
texto se puede importar **sin** tener una semilla previa en RAM.

### 6.2 Serial USB (desarrollo)

Protocolo binario `M5PSBT <len> <sha256>\n` + payload + `\nM5END\n`, con verificación
SHA256 y respuesta `READY`. También acepta `incommit-transaction: <base64>`.

### 6.3 BLE (oculto)

`qr_ble_client` implementa un cliente GATT (NimBLE) para recibir QR desde una
Raspberry Pi. Se migró de Bluedroid a **NimBLE** por los `configASSERT` internos
de Bluedroid en el M5Paper. No está accesible desde el menú.

---

## 7. Ajustes persistentes

`device_settings.hpp` gestiona `/m5settings.cfg` en la SD:

```
[0..3]   magia "M5CF"
[4]      versión = 2
[5]      idioma (0 = inglés, 1 = español)
[6]      derivación por defecto (0..2 = BIP44/49/84)
[7..10]  tiempo de bloqueo en ms (uint32 LE; 0 = nunca)
[11..14] tiempo de limpieza de seed en ms (uint32 LE; 0 = nunca)
```

Valores de bloqueo: 1/3/5/10 min o nunca (por defecto 3 min). Valores de limpieza
de seed: nunca/10/30/60 min (por defecto **nunca**); al agotarse borra **todas** las
semillas de RAM y cierra el vault de sesión, con una cuenta atrás de 15 s reutilizando
la pantalla de aviso. El idioma por defecto es **inglés**; toda la UI pasa por
`lang::tr()` con una tabla de traducción castellano→inglés.

---

## 8. i18n

Los literales del código están en castellano y sirven de clave; `lang::tr()`:

- Devuelve el propio literal si el idioma activo es español.
- Devuelve la versión inglesa (de la tabla en `lang.hpp`) si es inglés (por defecto).

Las funciones de render (título, botones, toasts, textos centrados) traducen
automáticamente; los textos dibujados directamente con `page.*` usan `lang::tr(...)`.

---

## 9. Navegación y UX

- Pantalla principal con 6 opciones + icono de ayuda (`?`) abajo a la derecha.
- Badge de fingerprint (arriba a la derecha) con icono de huella y valor FPR.
- Pantalla de bloqueo **estática** (sin animaciones, para no consumir batería en
  e-ink) que sirve tanto de salvapantallas como de pantalla de apagado.
- Auto-bloqueo por inactividad (conserva la semilla en RAM) y bloqueo manual
  (descarta la semilla).
- Navegación por palanca (rocker) y táctil con modelo de foco consistente.

---

## 10. Problemas conocidos / pendientes

- BBQr sin compresión Base32/zlib (optimización futura).
- El soporte Taproot (BIP86) fue **eliminado** temporalmente porque su
  self-test fallaba; queda como trabajo futuro.
- Soporte Ethereum (v2.0) — ver [`ETH_v2.0.md`](ETH_v2.0.md), sin implementar.

Nota: los hallazgos S-1 (blinding ECC), S-2 (limpieza de `String`) y S-3
(límite de iteraciones PBKDF2) de [`AUDITORIA.md`](AUDITORIA.md) ya fueron
corregidos.

---

## 11. Licencia

GNU General Public License v3.0 (o posterior) — ver [`LICENSE`](LICENSE).
