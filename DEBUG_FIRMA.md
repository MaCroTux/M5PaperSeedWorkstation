# Bitácora — Corrección del bug de firma Bitcoin (P2WPKH)

Documentación de cómo se localizó y corrigió el error que hacía que la red
rechazara las transacciones firmadas por el M5Paper.

**Resultado final**: las transacciones firmadas se validan y se emiten
correctamente tanto en **Sparrow** como en **BlueWallet**.

---

## 1. Síntoma

Al hacer *broadcast* de una transacción firmada por el M5Paper, la red la rechazaba:

```text
non-mandatory-script-verify-flag
(Signature must be zero for failed CHECK(MULTI)SIG operation)
```

Y, dentro del propio dispositivo, la autoverificación fallaba:

```text
[SIGN] SELF VERIFY FAILED
```

Es decir, la firma no validaba **ni localmente**.

---

## 2. Bugs encontrados (fueron dos)

### Bug 1 — `scriptCode` de P2WPKH mal construido

En `tx_sign.hpp`, el `scriptCode` para BIP143 se generaba con un byte espurio:

```cpp
// MAL (longitud 26, con 0x19 dentro del buffer)
uint8_t scriptCode[26] = {};
scriptCode[0] = 0x19;                       // ❌ sobra
scriptCode[1] = 0x76; scriptCode[2] = 0xa9; scriptCode[3] = 0x14;
memcpy(scriptCode + 4, in.utxoScript + 2, 20);
scriptCode[24] = 0x88; scriptCode[25] = 0xac;
```

Producía `19 76a914{hash}88ac` (26 bytes) cuando debe ser `76a914{hash}88ac`
(**25 bytes**). El byte `0x19` es la **longitud** del script y la serializa
`sighashSegwit()` como un varint en el preimage; **no** debe estar dentro del
buffer del script.

```cpp
// BIEN (25 bytes)
uint8_t scriptCode[25] = {};
scriptCode[0] = 0x76; scriptCode[1] = 0xa9; scriptCode[2] = 0x14;
memcpy(scriptCode + 3, in.utxoScript + 2, 20);
scriptCode[23] = 0x88; scriptCode[24] = 0xac;
sighashSegwit(tx, i, scriptCode, 25, in.amount, sighash);
```

### Bug 2 — mbedTLS no importa public keys SEC1 **comprimidas**

El autoverificador (`verify`) llamaba a:

```cpp
mbedtls_ecp_point_read_binary(&group, &Q, pub, 33);   // pub = 02/03 + X
```

y obtenía:

```text
readQ=-20096
```

`-20096 = -0x4E80 = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE`.

En esta build de mbedTLS (arduino-esp32), `mbedtls_ecp_point_read_binary()` **no
soporta el formato SEC1 comprimido** (`02/03 + X`, 33 bytes) y lo rechaza.

#### Corrección: descompresión previa

Se añadió `decompressPubkey()`, que convierte `02/03 + X` (33 bytes) a
`04 + X + Y` (65 bytes), calculando:

```text
y = sqrt(x³ + 7) mod p   =   (x³ + 7)^((p+1)/4) mod p
```

(esto es válido porque secp256k1 cumple `p ≡ 3 (mod 4)`), y luego ajusta la
paridad de `y` según el prefijo (`02` = par, `03` = impar).

```cpp
uint8_t pub65[65] = {};
decompressPubkey(pub, pub65);
mbedtls_ecp_point_read_binary(&group, &Q, pub65, 65);   // readQ = 0
```

---

## 3. Proceso de aislamiento (paso a paso)

El orden en que se descartaron causas fue clave para no tocar lo que ya estaba bien:

1. **BIP143 correcto** — se verificó que el `preimage` y el `sighash` coincidían
   (double-SHA256 del preimage verificado externamente).
2. **`scriptCode` correcto** tras el Bug 1.
3. **Clave correcta** — `HASH160(pubkey derivada) == witness program` (`pubkey_hash == witness_hash`).
4. **`amount`, `sequence`, `version`, `locktime`** — correctos (endianess OK).
5. **SELF VERIFY fallaba** → se acotó a la capa ECDSA.
6. Se sustituyó `mbedtls_ecdsa_verify()` por una **verificación manual**
   (`w = s⁻¹ mod n; u1 = e·w; u2 = r·w; R = u1·G + u2·Q; R.x mod n == r`),
   para no depender del formato que esperase esa API.
7. Siguen fallando → se añadieron **códigos de retorno** a cada llamada mbedTLS.
8. `readQ=-20096` delató el fallo exacto: la importación de la pubkey comprimida.

---

## 4. Cambios finales aplicados

| Archivo | Cambio |
|---|---|
| `tx_sign.hpp` | `scriptCode` P2WPKH corregido a 25 bytes. |
| `tx_sign.hpp` | `decompressPubkey()` nueva (SEC1 comprimido → sin comprimir). |
| `tx_sign.hpp` | `verify()` manual con aritmética mbedTLS + descompresión previa. |
| `tx_sign.hpp` | `derDecode()` nueva (DER → `R‖S`). |
| `tx_sign.hpp` | Autoverificación obligatoria (`SELF VERIFY`) antes de finalizar la TX. |
| `tx_sign.hpp` | `testECDSARoundtrip()` aislado (sign→verify sin Bitcoin) en el self-test de arranque. |
| `tx_sign.hpp` | Logs de diagnóstico (`[ECDSA]`, `[SIGN]`) sin exponer claves privadas. |

---

## 5. Verificación

```text
[ECDSA] RFC6979 sign=OK vector_match=OK
[ECDSA] rc: load=0 readQ=0 readR=0 readS=0 readE=0 rRange=1 sRange=1 inv=0
[ECDSA] muladd rc=0
[ECDSA] cmp(rx,r)=0
[ECDSA] native verify=OK
[ECDSA] DER roundtrip verify=OK
[SIGN] SELF VERIFY OK
```

Con esto, la transacción firmada se emitió correctamente en **Sparrow** y
**BlueWallet**.

---

## 6. Lecciones

- **No asumir** que una librería criptográfica soporta SEC1 comprimido. mbedTLS
  (en esta build) no lo hace para `mbedtls_ecp_point_read_binary`.
- **Autoverificar localmente** (`SELF VERIFY`) antes de generar/emitir una TX
  permite separar "bug en ECDSA" de "bug en el pipeline Bitcoin".
- **Loggear los códigos de retorno** de cada llamada criptográfica (p.ej.
  `-20096 = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE`) acota el fallo a una sola línea.
- **La raíz cuadrada modular** en secp256k1 es `a^((p+1)/4)` porque `p ≡ 3 (mod 4)`;
  conviene verificarlo con un vector conocido antes de usarlo.
