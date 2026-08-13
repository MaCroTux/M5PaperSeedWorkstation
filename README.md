# M5Paper Seed Workstation

**v1.1**

An offline workstation for BIP39 seeds, Bitcoin key/address derivation and
**PSBT transaction signing**, running on the **M5Paper** (ESP32 with a 540×960
e-paper display and GT911 touch).

> **WARNING**: this is test data only. **DO NOT USE WITH REAL FUNDS** until a
> formal security review is completed.

> **Note**: this project was built with **Vibe Coding**, as an **experiment**.
> Do not use it with real funds.

Documentación en español: [`README_ES.md`](README_ES.md).

---

## 1. What it does

- **Enter a BIP39 seed** (on-screen keyboard with autocomplete of the 2048 words).
- **Generate entropy** by drawing on screen or rolling dice.
- **Seed review & backup**: words, QR and **SEEDQR** (offline wizard).
- **Public key**: derive and display xpub/zpub (BIP32), with QR.
- **Address explorer**: derive P2PKH, P2SH, native segwit (BIP84) and taproot
  (BIP86) addresses, for receive and change, with a direct index jump.
- **BIP39 passphrase** (changes every derived address).
- **Individual vault**: one seed encrypted with its own password (`.vlt` file).
- **Session vault**: several seeds encrypted under one master password.
- **Receive via WiFi** (access point + captive portal) or **USB serial**: PSBT
  (file or text) or BIP39 seed as text (the latter works with no seed in RAM).
- **Sign PSBT** (segwit P2WPKH, ECDSA RFC6979 + BIP143) and broadcast:
  - **Sparrow**: static QR (hex of the signed transaction).
  - **BlueWallet**: animated **BBQr** QR (Base64 PSBT for small payloads,
    multipart `B$HPxxxx` for large payloads).
- **Settings** stored on SD: language (English by default / Spanish), auto-lock
  timeout (1/3/5/10 min or never), seed-wipe timeout (never/10/30/60 min),
  default derivation (BIP44/49/84/86) and radio status (BT/WiFi/power).
- **Lock** (manual or on inactivity) with a **static cover screen** (no animations,
  to save e-ink battery) that doubles as an off/screensaver screen.

---

## 2. Main menu

```
ENTER SEED            (type a BIP39 seed)
GENERATE ENTROPY      (draw or roll dice)
SESSION VAULT         (create/open a multi-seed vault)
RECEIVE VIA WIFI      (AP to receive a PSBT or seed from your phone)
SETTINGS              (language, lock, derivation, radio)
LOCK                  (lock the device with the cover screen)
```

**Help** is available through the `?` icon in the bottom-right corner of the main
menu (secondary option).

When a seed is active, the first entry becomes **ACTIVE SEED** and
"GENERATE ENTROPY" is disabled.

---

## 3. Signing flow (PSBT)

```
PSBT (WiFi or serial)
   ↓
M5Paper decodes and shows the transaction
   (PAYMENT / CHANGE / FEE + addresses in a box)
   ↓
[ DETAILS ] → list of UTXOs (inputs)
   ↓
[ SIGN ]    → signs each input (segwit P2WPKH)
   ↓
[ BROADCAST ] → SPARROW (static hex QR)  |  BLUEWALLET (BBQr QR)
   ↓
External wallet recognizes and broadcasts the transaction
```

Verified end-to-end: BlueWallet reads the signed transaction and the result
matches Coinb.in.

---

## 4. Receiving a PSBT / seed

### Via WiFi

1. **RECEIVE VIA WIFI** (main menu or active-seed menu).
2. Choose the input mode:
   - **UPLOAD FILE (PSBT)**: upload a `.psbt` file (requires a loaded seed).
   - **PASTE TRANSACTION (PSBT)**: paste the PSBT as text (base64, hex or UR) (requires a loaded seed).
   - **PASTE BIP39 SEED**: import a 12/24-word seed (no prior seed required).
3. The M5Paper creates an AP `M5Paper-QR` (random key) with a **connection QR**
   and a **captive portal** adapted to the chosen mode.
4. Scan the QR with your phone, connect, and the web page opens automatically.
5. Upload/paste the content. The AP turns off automatically once received.

### Via serial (development)

```bash
python3 PSBTSerialSend.py transaction.psbt
```

Protocol: `M5PSBT <len> <sha256>\n` + binary payload + `\nM5END\n`.
The M5Paper replies `READY` and verifies the SHA256 before processing.

It also accepts `incommit-transaction: <base64>` as a text command.

---

## 5. File layout

| File | Role |
|---|---|
| `NativeApp.cpp` | Main UI (M5EPD): screens, navigation, state machine. |
| `M5PaperSeedWorkstation.ino` | Sketch entry point (the UI lives in `NativeApp.cpp`). |
| `bip39_support.hpp` | BIP39 list, prefix search, checksum, `from_entropy`, self-tests. |
| `bitcoin_hd.hpp` | BIP32: BIP39→seed, hardened/normal derivation, xpub/zpub, base58check. |
| `bitcoin_address.hpp` | P2PKH/P2SH/native segwit/taproot addresses (bech32, bech32m). |
| `bitcoin_fingerprint.hpp` | Master key fingerprint. |
| `ripemd160_min.hpp` | RIPEMD-160. |
| `encrypted_seed_store.hpp` | Individual vault: AES-256-GCM + PBKDF2. |
| `session_vault_store.hpp` | Session vault: master key + seeds. |
| `psbt_parser.hpp` | PSBT parser (BIP174) + transactions, binary/base64/hex/UR detection. |
| `ur_psbt.hpp` | `UR:CRYPTO-PSBT` decoding (bytewords + CBOR). |
| `tx_sign.hpp` | Segwit signing: RFC6979, BIP143 sighash, finalization & serialization. |
| `bbqr.hpp` | BBQr encoding (BIP-129 / Coinkite): `B$HPxxxx` header + hex. |
| `seedqr_qrcode.c/.h` | QR generation (MIT license). |
| `generated/bip39_english.h` | The 2048 words in PROGMEM. |
| `qr_wifi_server.hpp` | WiFi access point + HTTP server + captive portal. |
| `qr_ble_client.hpp/.cpp` | BLE client (NimBLE) — **hidden in the menu, not removed**. |
| `lang.hpp` | EN/ES translation (`lang::tr`) with a Spanish→English table. |
| `device_settings.hpp` | SD-persisted settings (`/m5settings.cfg`): language, lock, derivation. |
| `AUDITORIA.md` | Security & UX audit (Spanish). |
| `TECHNICAL.md` | Detailed technical documentation. |
| `DEBUG_FIRMA.md` | Post-mortem of the P2WPKH signing bug (Spanish). |

---

## 6. Building

### PlatformIO (compile validation)

```bash
~/.platformio/penv/bin/pio run -e native
```

The `native` environment uses `espressif32@5.0.0` (arduino-esp32 core **2.0.3**),
board `m5stack-fire`, `M5EPD` from `~/Documents/Arduino/libraries/M5EPD` and
`NimBLE-Arduino@^1.4.0`.

### Arduino IDE (real build / flashing)

- Board: **M5Stack-FIRE**, core **esp32 2.0.3**.
- Libraries in `~/Documents/Arduino/libraries`: `M5EPD`, `NimBLE-Arduino` (v1.4.x).

Reliable flashing over marginal USB: `esptool.py --no-stub --baud 115200 write_flash 0x10000 firmware.bin`.

---

## 7. Security design

- **Encryption at rest**: AES-256-GCM with the full header as AAD; detects
  tampering of salt, nonce and metadata.
- **Key derivation**: PBKDF2-HMAC-SHA256 with **600,000 iterations** and a random
  16-byte salt per file (hardware RNG `esp_fill_random`).
- **Signing**: ECDSA secp256k1 with **deterministic nonce RFC6979** + **low-S**;
  **BIP143** sighash (segwit v0). BIP32 path verified via master fingerprint.
- **Memory wiping**: `wipe()` (volatile) over keys, plaintext, seed buffers, etc.
- **Auto-lock** on inactivity (configurable) plus manual lock.
- **Boot self-tests**: BIP39, BIP32, fingerprint, PBKDF2 (against
  `mbedtls_pkcs5_pbkdf2_hmac`), ECDSA (RFC6979), PSBT parser, BIP84/BIP86 addresses.

---

## 8. Bluetooth (hidden, not removed)

BLE client (`qr_ble_client.hpp/.cpp`) to receive a QR from a Raspberry Pi
(`M5Paper-QR` GATT server), **disabled** in the menu. Bluedroid was replaced with
**NimBLE** because Bluedroid produced internal `configASSERT` on the M5Paper.

---

## 9. Status / backlog

- [x] WiFi AP reception (captive portal + connection QR) with 3 modes.
- [x] USB serial reception (`M5PSBT` protocol + SHA256).
- [x] `UR:CRYPTO-PSBT` decoding (Sparrow QR).
- [x] PSBT signing (segwit P2WPKH) + static QR (Sparrow) and BBQr (BlueWallet).
- [x] SD-persisted settings (language, lock, derivation, radio).
- [x] Full EN/ES translation.
- [ ] Fix the **BIP86** self-test (fails; BIP84 OK).
- [ ] Base32 and zlib in BBQr (future optimization).

---

## 10. Usage warning

This firmware handles private keys. Do not use with real funds until a formal
security review and exhaustive physical testing are completed.
