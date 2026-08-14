# PROTOCOLO DE PROVISIONING — M5Paper → M5Stick

Protocolo BLE para transferir una seed (mnemonic BIP39) desde el M5Paper
(Seed Workstation) al M5Stick (Pocket Signer). Este documento es la referencia
única de cable para ambos lados: el M5Paper implementa el cliente, el M5Stick
implementa el servidor.

## 1. Roles

| Dispositivo | Rol BLE | Rol funcional |
|---|---|---|
| M5Paper | Central (cliente) | Inicia, cifra y envía la seed |
| M5Stick | Peripheral (servidor) | Anuncia en modo importación, descifra y acepta |

El M5Stick, al entrar en "IMPORT SEED", genera (o reutiliza) un par de claves de
identidad y anuncia. El M5Paper escanea, se conecta y envía la seed cifrada.

## 2. Qué se transfiere

- **Mnemonic BIP39**: `count` (12 o 24) + índices de palabras (`uint16_t`
  little-endian, mismo formato que el M5Paper usa en disco).
- **Fingerprint**: 4 bytes (`SHA256(SHA256(seed))[0..4]`, estándar BIP32).

No se transfiere passphrase ni derivación en esta versión.

## 3. Seguridad en tránsito

ECIES sobre **secp256k1**:

1. El M5Stick expone su **clave pública sin comprimir** (65 bytes, `0x04 || X || Y`).
2. El M5Paper genera un par efímero `(e, E)`, deriva
   `K = SHA256( x(ECDH(e, pk_stick)) || "m5-stick-provision-v1" )`.
3. La seed se cifra con **AES-256-GCM** usando `K` (nonce de 12 bytes aleatorio,
   tag de 16 bytes).
4. Se envía `E || nonce || ciphertext || tag`.

La seed **nunca** viaja en claro. Confirmación física requerida en **ambos**
dispositivos.

## 4. Identificadores BLE

| Elemento | Valor |
|---|---|
| Nombre del dispositivo | `M5Stick-Signer` |
| Service UUID | `e5b20001-7a1e-4b9c-8d2f-3c6b1a4d0001` |
| `PROV_PUBKEY` (READ) | `e5b20002-7a1e-4b9c-8d2f-3c6b1a4d0001` |
| `PROV_REQ` (WRITE) | `e5b20003-7a1e-4b9c-8d2f-3c6b1a4d0001` |
| `PROV_STATUS` (READ \| NOTIFY) | `e5b20004-7a1e-4b9c-8d2f-3c6b1a4d0001` |

## 5. Características

### 5.1 `PROV_PUBKEY` — READ
- Clave pública secp256k1 **sin comprimir** del M5Stick: **65 bytes**.
- Debe ser la clave de identidad persistente del M5Stick (guardada en NVS),
  no una efímera por conexión.

### 5.2 `PROV_REQ` — WRITE
- Blob ECIES enviado por el M5Paper:
  `E(65) || nonce(12) || ciphertext(N) || tag(16)`
- `N` = longitud del payload en claro (29 bytes para 12 palabras, 53 para 24).

### 5.3 `PROV_STATUS` — NOTIFY (y READ)
- **1 byte**. Valores:

| Código | Nombre | Significado |
|---|---|---|
| `0` | `idle` | Sin operación en curso |
| `1` | `requested` | Seed recibida, esperando confirmación física |
| `2` | `accepted` | Seed aceptada e importada (continúa con CREATE PIN) |
| `3` | `denied` | Rechazada por el usuario |
| `4` | `error` | Fallo (descifrado, formato, tamaño, etc.) |

## 6. Payload en claro (antes de cifrar)

```
byte 0                     : count (12 o 24)
bytes 1 .. count*2         : índices de palabras, uint16 little-endian
bytes count*2+1 .. count*2+4 : fingerprint (4 bytes)
```

Longitud total = `1 + count*2 + 4`.

## 7. Detalles criptográficos

- Curva: `secp256k1` (`MBEDTLS_ECP_DP_SECP256K1`).
- Clave pública: **sin comprimir** (65 bytes) para evitar el fallo de
  descompresión de punto comprimido en mbedtls 2.28.
- Derivación de clave: `K = SHA256( x(ECDH(priv, theirPub)) || tag )` con
  `tag = "m5-stick-provision-v1"`.
- Cifrado: AES-256-GCM, nonce aleatorio de 12 bytes, tag de 16 bytes.
  Formato del cifrado: `nonce(12) || ciphertext || tag(16)`.
- Dominio de separación: usar el tag `m5-stick-provision-v1` (distinto del tag
  de desbloqueo de vault con el M5Core2, `m5-vault-ecies-v1`).

## 8. Flujo completo

```
M5Stick                                 M5Paper
  |-- (modo IMPORT SEED) ----------------|
  |   genera/lee keypair, anuncia        |
  |<--------- scan / connect ------------|
  |-- PROV_PUBKEY (65 B) --------------->|  lee pk_stick
  |                                      |  arma payload (count||words||fpr)
  |                                      |  genera (e,E), K = ECDH(e, pk_stick)
  |                                      |  ECIES(payload)
  |<-- PROV_REQ (E||nonce||ct||tag) -----|  escribe blob
  |  descifra, valida                    |
  |  muestra "IMPORT SEED? FPR ..."      |
  |  NOTIFY requested ------------------>|  M5Paper muestra "esperando..."
  |  (usuario: HOLD CENTER para aceptar) |
  |  acepta -> NOTIFY accepted --------->|  M5Paper muestra "PROVISIONADO"
  |  (continúa con CREATE PIN)           |
  |   o rechaza -> NOTIFY denied ------->|
  |   o falla -> NOTIFY error ---------->|
```

Confirmación física:
- **M5Paper**: confirma (HOLD) antes de enviar la seed.
- **M5Stick**: `HOLD CENTER` para aceptar la importación.

## 9. Requisitos para el M5Stick

- Cifrar/guardar la seed **inmediatamente** al recibirla; nunca persistirla en
  claro.
- La clave de identidad (`sk_stick`/`pk_stick`) debe persistir en NVS.
- El fingerprint mostrado debe derivarse de las palabras recibidas y mostrarse
  para comparación visual.
- Tras `accepted`, iniciar el flujo `CREATE PIN`.
- Rechazar blobs con tamaño o formato incorrectos notificando `error`.

## 10. Notas

- Este protocolo cubre únicamente el **provisioning**. La devolución del PSBT
  firmado usa USB/WiFi/QR, no BLE.
- Implementación de referencia del lado M5Paper: `ble_provision.hpp` y
  `ble_provision_client.*` en `lib/seedworkstation_core/src`.
