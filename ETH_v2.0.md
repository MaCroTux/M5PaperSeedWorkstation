# Propuesta v2.0 — Soporte Ethereum (diseño)

> Documento de diseño. **No implementado todavía.**
> Estado: borrador para discusión, basado en la arquitectura de la v1.1.

---

## 1. Objetivo

Ampliar M5Paper Seed Workstation para que, además de Bitcoin, permita **derivar
direcciones Ethereum y firmar transacciones ETH** de forma offline. La semilla
BIP39 es la misma; el dispositivo pasa a ser una *workstation multi-cadena*.

**Alcance mínimo (v2.0):**
1. Derivar y mostrar la dirección ETH con checksum **EIP-55**.
2. QR de recepción (URI **EIP-681** `ethereum:0x…`).
3. Firmar una transacción cruda recibida por WiFi/serial (RLP + **EIP-155**).

---

## 2. Qué se reutiliza de la v1.1

| Componente | Reutilización |
|---|---|
| BIP39 (teclado, entropía, checksum, wordlist) | 100% — mismo estándar BTC/ETH. |
| Curva **secp256k1** (mbedTLS) | 100% — ETH usa la misma curva. |
| Derivación BIP32 (endurecida/normal) | Parcial — hay que separar lo específico de Bitcoin (claves comprimidas). |
| Vaults AES-256-GCM + PBKDF2 | 100% — cifrado en reposo independiente de la cadena. |
| UI e-ink, navegación, ajustes, i18n | 100%. |
| WiFi/serial (recepción) | Parcial — nuevo payload de transacción ETH. |

---

## 3. Qué es nuevo

### 3.1 Keccak-256

- **No** es SHA3-256 (aunque se parecen); el NIST cambió el *padding*.
- mbedTLS no lo incluye: hay que implementarlo (~150 líneas C, bien conocido y
  testable contra vectores oficiales).
- Se usa para: la dirección (`keccak256(pubkey)[12:]`), el hash de la transacción
  y el *personal message* (EIP-191).

### 3.2 Clave pública sin comprimir

- Bitcoin usa claves **comprimidas** (33 bytes, prefijo `02`/`03`).
- Ethereum usa la clave **sin comprimir** (64 bytes `x ‖ y`) para el keccak.
- `bitcoin_hd.hpp` deriva comprimida; hay que exponer también la forma `x‖y`.

### 3.3 Formato de firma

- Ethereum firma ECDSA/secp256k1 con **recovery-id** → firma de 65 bytes `(r, s, v)`.
- Reglas obligatorias: **EIP-2** (low-S) y **EIP-155** (chain-id para anti-replay).
- El "sighash" es el **hash keccak del RLP** de los campos de la transacción
  (incluido el chain-id), no tiene relación con BIP143.

### 3.4 RLP y tipos de transacción

- RLP (*Recursive Length Prefix*) para serializar: `nonce, gasPrice, gasLimit,
  to, value, data, v, r, s` (legacy) o los campos de **EIP-1559**
  (`maxFeePerGas`, `maxPriorityFeePerGas`, `accessList`).
- v2.0 debe soportar al menos **legacy + EIP-1559** (el estándar actual).

### 3.5 Dirección y checksum

- Dirección = últimos 20 bytes de `keccak256(pubkey)`.
- **EIP-55**: checksum por mayúsculas/minúsculas derivado de `keccak256` del hex.

---

## 4. Arquitectura propuesta

Separar el núcleo HD de la cadena concreta:

```
BIP39 mnemonic
   └─ PBKDF2-HMAC-SHA512 (2048)  →  seed (64 B)      [bip39_support.hpp]
        └─ BIP32 root (secp256k1)                     [hd_core]  ← nuevo, agnóstico
             ├─ Bitcoin:  comprimida → HASH160 → bech32/base58   [btc]
             └─ Ethereum: sin comprimir → keccak256 → EIP-55     [eth]  ← nuevo
```

Módulos nuevos:

| Fichero (propuesta) | Rol |
|---|---|
| `keccak256.hpp` | Keccak-256 puro + self-test contra vectores oficiales. |
| `eth_address.hpp` | Dirección + EIP-55 + URI EIP-681. |
| `eth_tx.hpp` | RLP (encode/decode), nonce/gas/chain-id. |
| `eth_sign.hpp` | Firma legacy + EIP-1559, EIP-2/EIP-155, recovery-id. |
| `hd_core.hpp` | (refactor) derivación BIP32 independiente de la cadena. |

El flujo de UI sería análogo al de Bitcoin: elegir red → derivar/dirección → recibir
transacción por WiFi/serial → verificar → firmar → QR (o hex para emisión manual).

---

## 5. Comunicaciones y QR

- **Entrada**: transacción cruda ETH (RLP) por WiFi/serial, análogo a `M5PSBT`.
  Podría aceptarse EIP-681 (`ethereum:0x…?value=…&data=…`) para construir una tx.
- **Salida**: transacción firmada como hex (para `SendRawTransaction`) o QR de
  `ethereum:tx-<hex>`.

---

## 6. Testing / vectores

- Keccak-256: vectores de `eth-hash` / Keccak test-suite.
- EIP-55: casos oficiales (p.ej. `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`).
- Firmas: vectores de transacciones legacy y EIP-1559 conocidas (txid y `v`).
- RLP: casos de *round-trip* y ejemplos del Yellow Paper.

---

## 7. Riesgos y advertencias

- **Errores de firma = pérdida de fondos o replay**: chain-id, low-S, campos de gas
  y RLP son los puntos críticos.
- **No usar con fondos reales** hasta auditoría (igual que BTC).
- La interacción típica ETH es vía dApp (EIP-712 *typed data*); en una pantalla
  e-ink pequeña es incómodo. v2.0 se limita a **direcciones + transacciones crudas**,
  no a *personal_sign* / EIP-712 interactivo.

---

## 8. Versión y prioridades

- **v2.0**: refactor HD + keccak256 + dirección/QR + firma legacy/EIP-1559.
- Posibles v2.x: EIP-712, soporte multi-chain EVM, tokens ERC-20, BIP44 multi-account.

Prioridad de implementación sugerida:

1. `hd_core.hpp` (separar BIP32 de Bitcoin) + `keccak256.hpp`.
2. `eth_address.hpp` (EIP-55 + QR de recepción).
3. `eth_tx.hpp` (RLP) + `eth_sign.hpp` (EIP-155) + integración UI/WiFi.
