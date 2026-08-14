# AUDITORÍA — M5PaperSeedWorkstation

Auditoría de seguridad y de lógica de navegación (UIX) del proyecto M5PaperSeedWorkstation.
Alcance: revisión estática del código, sin modificación de archivos.

Fecha: 2026-08-12
Versión de firmware revisada: `native-passphrase-4` (NativeApp.cpp) y `phase2-partial-refresh-2` (legacy .ino).

---

## 1. Resumen ejecutivo

El proyecto es un prototipo de *workstation* offline sobre M5Paper para manejar
semillas BIP39 y derivar claves/direcciones Bitcoin. La calidad criptográfica del
núcleo es buena: usa AES-256-GCM con AAD sobre toda la cabecera, PBKDF2-HMAC-SHA256
con 600.000 iteraciones, sal y nonce de 96 bits generados por el RNG de hardware
(`esp_fill_random`), y verificación de integridad (fingerprint + checksum BIP39) al
recuperar. Hay un esfuerzo sistemático por limpiar la memoria (funciones `wipe`).

**No se encontró ninguna vulnerabilidad crítica que rompa la criptografía.** Los
hallazgos principales son de endurecimiento (side-channels, limpieza de cadenas,
DoS por valor de iteraciones) y, sobre todo, de coherencia de la interfaz y de la
navegación: hay bugs reales de lógica de menús (rama muerta, roca invertida,
redirecciones sorpresivas) y dos árboles de UI en paralelo que han divergido.

---

## 2. Estructura del proyecto

| Archivo | Rol |
|---|---|
| `M5PaperSeedWorkstation.ino` | UI legacy (M5Unified/M5GFX), activa solo con `LEGACY_M5GFX_BUILD`. 6 pantallas. |
| `NativeApp.cpp` | UI nativa M5EPD, es la implementación principal (28 pantallas). |
| `bip39_support.hpp` | Lista BIP39, búsqueda de prefijos, checksum, from_entropy, self-tests. |
| `bitcoin_hd.hpp` | BIP32/BIP39→seed, derivación endurecida/normal, xpub/zpub, base58check. |
| `bitcoin_address.hpp` | Direcciones P2PKH/P2SH/native segwit/taproot (bech32, bech32m). |
| `bitcoin_fingerprint.hpp` | Fingerprint de la clave maestra. |
| `ripemd160_min.hpp` | RIPEMD-160 mínimo. |
| `encrypted_seed_store.hpp` | Almacén individual: AES-GCM + PBKDF2 (`.vlt`). |
| `session_vault_store.hpp` | Vault de sesión: clave maestra + semillas (`.svm` / `.svs`). |
| `seedqr_qrcode.c/.h` | Generación QR (licencia MIT). |
| `generated/bip39_english.h` | 2048 palabras en PROGMEM. |

---

## 3. Hallazgos de seguridad

### 3.1 Severidad MEDIA

**S-1. Operaciones de curva elíptica no son de tiempo constante**
La derivación de claves usa `mbedtls_ecp_mul` y `mbedtls_ecp_muladd` sin
aleatorización (*blinding*), que en mbedTLS no es constante en tiempo por defecto.
En un dispositivo que maneja claves privadas, un atacante con acceso físico
(análisis de potencia/timing) podría extraer material sensible.
- `bitcoin_hd.hpp:54` (`public_key`), `bitcoin_address.hpp:87` (`taproot_program`),
  `bitcoin_fingerprint.hpp:42`.
- Las rutas `derive_hardened`/`derive_normal` (`bitcoin_hd.hpp:75-129`) operan con
  aritmética modular mbedTLS (`mbedtls_mpi_*`), también sin blindaje.
- Mitigación recomendada: `mbedtls_ecp_mul(..., mbedtls_ecp_gen_privkey ..., f_rng, p_rng)`
  o habilitar `MBEDTLS_ECP_*` con contramedidas; no crítico para un prototipo
  "no usar fondos reales", pero sí para una futura versión productiva.

**S-2. Cadenas `String` con datos sensibles no se limpian de forma fiable**
La semilla mnemónica se reconstruye en un `String` de Arduino y al final se hace
`mnemonic = ""; salt = "";`, que **no** sobreescribe la memoria anterior (solo
reasigna el puntero; el heap de Arduino puede conservar copias intermedias).
- `bitcoin_hd.hpp:27-43` (`mnemonic_seed`), `bitcoin_fingerprint.hpp:14-58`
  (`calculate`).
- Mismo patrón con `publicExtendedKey` / `activeAddress` (no secretos, pero etiquetados
  como "datos sensibles" en la UI).
- Recomendación: acumular en `char[]` fijo y usar `wipe()`, o limpiar el contenido
  antes de desasignar.

**S-3. El contador de iteraciones PBKDF2 se confía del archivo (DoS potencial)**
En `load`, las iteraciones se leen de la cabecera y solo se valida un mínimo
(`iterations < 100000`).
- `encrypted_seed_store.hpp:100-101`, `session_vault_store.hpp:72-73`.
- Un archivo manipulado puede fijar `iterations = 0xFFFFFFFF` y provocar un PBKDF2
  de duración arbitraria (congelación del dispositivo). Falta un límite superior
  y/o fijar el valor al escrito por `save` (600.000).

### 3.2 Severidad BAJA

**S-4. Fuga de información por Serial (solo en la versión legacy)**
En el `.ino` legacy se imprime el prefijo de palabra que se está tecleando:
- `M5PaperSeedWorkstation.ino:387` (`BIP39 input: %s`), `:392` (`rejected prefix`),
  `:422` (`word not complete`).
- No revela la semilla completa, pero sí prefijos de palabras de la frase mnemónica.
  `NativeApp.cpp` ya eliminó estos logs (coherencia a favor de NativeApp).
- También se imprimen fingerprints y nombres de archivo (privacidad, no secreto).

**S-5. Búsqueda BIP39 no constante en tiempo**
`find_exact`/`find_matches` recorren las 2048 palabras con `strncmp`/`equals`
(`bip39_support.hpp:16-46`). El tiempo de búsqueda depende del prefijo. No es
explotable de forma remota, pero en un ataque físico podría ayudar a acotar palabras.

**S-6. Sin límite de intentos de desbloqueo en el dispositivo**
No hay bloqueo por reintentos de contraseña. Mitigado parcialmente por PBKDF2 de
600.000 iteraciones y porque la tarjeta SD puede extraerse; aun así, conviene un
*rate-limit* y borrado tras N intentos.

### 3.3 Observaciones correctas (verificadas)

- **Buffers QR correctos**: `qrcode_getBufferSize` (`seedqr_qrcode.c:772`) devuelve
  `ceil(size²/8)`; version 2 → 79 B, version 3 → 106 B. `seedqrBuffer[128]` es
  suficiente. `publicKeyQrBuffer[512]` (v6 = 211 B) y `addressQrBuffer[256]`
  (v4 = 137 B) también.
- **GCM bien usado**: nonce de 12 bytes aleatorio por archivo, cabecera completa como
  AAD (detecta manipulación de sal, nonce, metadatos), tag de 16 bytes.
  `encrypted_seed_store.hpp:53-78`, `session_vault_store.hpp:38-58`.
- **PBKDF2-HMAC-SHA256 600k** para vault individual y para la clave maestra de sesión;
  las semillas del vault de sesión se cifran con esa clave maestra (sin PBKDF2 extra).
  `session_vault_store.hpp:92-116`.
- **RNG**: `esp_fill_random` (hardware) + `bootloader_random_enable/disable` gestionados.
  `NativeApp.cpp:601-625`.
- **Limpieza**: `wipe()` usa `volatile` para evitar que el compilador elimine la
  operación (`encrypted_seed_store.hpp:18-21`). Se aplica a claves, plaintext, tag, etc.
- **Auto-bloqueo de sesión**: inactividad 180 s → `lockSessionVault()` que borra la
  clave maestra y descarta semillas (`NativeApp.cpp:2882-2886`, `:1460-1472`).
- **Verificación al guardar**: tras `save`, se re-lee y compara (`saveVault`,
  `saveSeedToSession`) antes de dar por bueno el archivo (`NativeApp.cpp:1153-1163`).

### 3.4 Defensa en profundidad (INFO)

- `session_vault_store::save_seed` **no** valida `words[i] < 2048` antes de empaquetar,
  a diferencia de `encrypted_seed_store::save` (`session_vault_store.hpp:105-108`).
  No es explotable porque las palabras provienen de entradas BIP39 ya validadas, pero
  rompe la simetría de validación.
- El "chequeo de salud" del RNG en la pantalla de entropía solo detecta valores
  consecutivos idénticos de `esp_random()` (prácticamente imposible); el indicador
  `RNG: FISICO` es decorativo, no una verificación real (`NativeApp.cpp:676-679`).
  La seguridad real depende del RNG de hardware, que sí es sólido.

---

## 4. Lógica de menús y navegación (UIX)

La navegación general es coherente: hay patrón consistente de "VOLVER" (`kBack`),
confirmación para acciones destructivas (`delete_confirm`, `discard_confirm`) y
advertencia de seguridad (`security_warning`) antes de mostrar la semilla o el QR.

### 4.1 Bugs / incoherencias concretas

**U-1. Direcciones de la palanca (rocker) invertidas en NativeApp**
- `NativeApp.cpp:2893-2894`: `izquierda → moveFocus(+1)`, `derecha → moveFocus(-1)`.
- En la versión legacy es al revés: `M5PaperSeedWorkstation.ino:668-679`
  (`izquierda → move_focus(-1)`).
- Resultado: en la app nativa, pulsar **izquierda** avanza al siguiente elemento y
  **derecha** retrocede, lo cual es anti-intuitivo e inconsistente con la referencia
  legacy. Probable regresión de la migración.

**U-2. Rama muerta y etiqueta engañosa "GUARDAR EN SESION"**
- `NativeApp.cpp:2466-2469`: dentro del bloque `else if (!sessionUnlocked &&
  kActiveMenu[3].contains(x, y))` existe `if (sessionUnlocked) beginSessionSave();`,
  condición que **siempre es falsa** (el bloque exterior ya exige `!sessionUnlocked`).
- Efecto: el botón "GUARDAR EN SESION" (índice 3, backup sin sesión) **nunca guarda**;
  solo navega a `session_menu`. La etiqueta promete una acción de guardado que no
  ocurre en ese punto. Código confuso que debe limpiarse.

**U-3. Redirección sorpresiva desde el menú principal**
- `NativeApp.cpp:2389`: si ya hay una semilla activa (`fingerprintValid`), tanto
  "INTRODUCIR SEMILLA" como "GENERAR ENTROPIA" abren `active_seed`, no la entrada de
  semilla ni la generación de entropía.
- El usuario que pulsa "GENERAR ENTROPIA" ve el menú de la semilla activa sin aviso.
  Es una decisión de diseño defendible (evitar sobrescribir), pero debería deshabilitar
  visualmente esas opciones o mostrar un mensaje explicativo.

**U-4. Funcionalidad oculta (solo táctil) en el badge de fingerprint**
- `NativeApp.cpp:2378`: el badge superior derecho (`kFingerprintBadge`) abre el selector
  de semillas (con sesión) o la clave pública (sin sesión), pero **no** es alcanzable
  mediante la palanca/foco. Descubribilidad nula para navegación por botones.

**U-5. Controles no accesibles por foco**
- En `address_explorer` solo `MENU SEED` y `QR DIRECCION` tienen foco; los botones
  `RECIBIR`, `CAMBIO`, `-1`, `+1` y `TIPO` son solo táctiles
  (`NativeApp.cpp:2300-2303`, `moveFocus` cuenta=2).
- En `dice`, las caras 1-6 son solo táctiles. No es un problema de seguridad, pero
  rompe la coherencia de un sistema que mezcla palanca y táctil.

**U-6. Estado de selección incoherente en DIAGNOSTICO**
- `NativeApp.cpp:2093`: el único botón "VOLVER" se dibuja siempre como seleccionado
  (`selected=true` fijo), ajeno al modelo `focusIndex`. Es un caso especial que debería
  unificarse.

**U-7. Cancelar la advertencia de seguridad descarta la intención**
- `NativeApp.cpp:2592`: al pulsar CANCELAR en `security_warning` se fuerza
  `newSeedIntent = None`. Si el usuario estaba creando una semilla "para el vault" y
  cancela la advertencia, pierde silenciosamente ese contexto. Podría confundir.

**U-8. "TIRAR DADOS" ignora la longitud elegida**
- Desde `entropy_length` el botón "TIRAR DADOS" entra en `dice` forzando 12 palabras
  (`diceTargetWords = 12`, `NativeApp.cpp:2559`), sin respetar la selección 12/24 de
  la pantalla anterior. La longitud se vuelve a elegir dentro de `dice`, pero el salto
  es incoherente con la pantalla de origen.

### 4.2 Mapa de flujo (resumen)

```
MENU (4) ─ INTRODUCIR SEMILLA ─ length(12/24) ─ keyboard ─ review ─ [seguridad] ─ plain_qr
        ├─ GENERAR ENTROPIA ─ entropy_length ─ entropy (dibujo)
        │                                    └ dice (lanzamientos)
        ├─ VAULT DE SESION ─ session_menu ─ crear/desbloquear ─ session_seed_list ─ ...
        └─ DIAGNOSTICO

SEMILLA ACTIVA (5/6) ─ VER CLAVE PUBLICA ─ public_key ─ public_key_qr
                    ├─ BACKUP SEED ─ backup_seed ─ (VER PALABRAS / VER QR / SEEDQR / GUARDAR)
                    ├─ PASSPHRASE ─ passphrase_input
                    ├─ EXPLORAR DIRECCIONES ─ address_explorer ─ address_qr
                    ├─ DESCARTAR SEED ─ discard_confirm
                    └─ ACCIONES EN VAULT / CERRAR VAULT (solo con sesión)
```

El flujo es, en general, jerárquico y con rutas de retorno correctas. Los problemas
están en los casos de borde listados arriba, no en la arquitectura general.

### 4.3 Duplicación de UI (deuda técnica)

Existen dos árboles de UI en paralelo:
- `NativeApp.cpp` (activo, M5EPD, 28 pantallas).
- `M5PaperSeedWorkstation.ino` (legacy, M5GFX, 6 pantallas), compilado solo con
  `LEGACY_M5GFX_BUILD`.

Ya han divergido (por ejemplo, la palanca invertida U-1). Riesgo de mantenimiento:
cambios de seguridad en un árbol no se propagan al otro. Además, en el legacy hay un
typo: `M5PaperSeedWorkstation.ino:5` usa `#ifndef ARDUINO_M5STACK_PAPERcomo` (nombre
erróneo), por lo que la macro se define siempre. Conviene consolidar en una sola UI.

---

## 5. Recomendaciones priorizadas

1. **Corregir la palanca invertida (U-1)** y unificar la dirección de navegación.
2. **Limpiar la rama muerta y la etiqueta "GUARDAR EN SESION" (U-2)**; hacer que el
   botón o bien guarde directamente o se renombre a "ABRIR VAULT DE SESION".
3. **Limitar/validar las iteraciones PBKDF2** en `load` (S-3) con un techo (p.ej. igual
   al valor de escritura) para evitar DoS.
4. **Blindar o documentar las operaciones ECC** (S-1) antes de cualquier uso con fondos
   reales.
5. **Sustituir los `String` sensibles por buffers fijos con `wipe`** (S-2).
6. **Eliminar los logs de prefijos de palabras del serial legacy** (S-4).
7. **Añadir rate-limit / bloqueo de intentos** en el desbloqueo de vault (S-6).
8. **Hacer accesibles por foco** los controles táctiles de `address_explorer` y `dice`
   (U-5), o documentar explícitamente qué es solo táctil.
9. **Consolidar una única UI** y eliminar el código legacy o alinearlo (U-3, deuda).
10. **Sincronizar la validación** de `words[i] < 2048` en `session_vault_store::save_seed`
    (3.4).

---

## 6. Conclusión

El núcleo criptográfico es sólido y está bien pensado (AES-GCM + PBKDF2 + verificación
integral, limpieza de memoria, auto-bloqueo). Los problemas de seguridad son de
endurecimiento y de robustez frente a adversarios físicos, no de rotura del esquema.
El mayor riesgo observable hoy es de **UX/navegación**: la palanca invertida, la rama
muerta en "GUARDAR EN SESION" y las redirecciones sorpresivas pueden llevar al usuario
a interpretar mal el estado de su semilla, lo que en un dispositivo de este tipo es
también un riesgo de seguridad.

---

## 7. Addendum 2026-08-14 — Llave BLE (M5Core2) como llave asimétrica

Alcance: revisión estática de la llave criptográfica BLE (`ble_key.hpp`,
`ble_key_client.*`, `ble_key_server.*`, `vault_key.hpp`) y su integración en
`NativeApp.cpp` / `NativeApp_Core2.cpp`, en el modelo **asimétrico**: el Core2
guarda la privada `sk` (cifrada con PIN) y el M5Paper solo guarda la pública `pk`.

### 7.1 Hallazgos

**BL-1 (MEDIA). `sk` protegida por PIN de 6 dígitos (20 bits) en reposo.**
`sk` se guarda cifrada con `K_pin = PBKDF2(PIN, 150k)`. Mejora respecto al diseño
anterior (la privada ya no va en claro), pero un volcado de flash del Core2 permite
fuerza bruta offline del PIN (~2^37). El factor limitante sigue siendo la entropía
del PIN, no la ubicación. Recomendación: PIN/frase más larga.

**BL-2 (MEDIA). ECC sin *blinding* (recurrencia de S-1).**
`derivePublicKey`/`deriveEcdhKey` usan `mbedtls_ecp_mul(..., NULL, NULL)`. El ECDH
maneja `sk` (privada de largo plazo del Core2) en el Core2. Misma clase que S-1.

**BL-3 (MEDIA). Intercambio de `pk` sin confirmación *out-of-band* (MITM).**
El emparejamiento lee `pk` de quien anuncie `M5Core2-Key`; un adversario activo
podría dar su propia `pk`. La confirmación física `AUTHORIZE` mitiga pero no elimina
el ataque. Recomendación: huella visual corta (p. ej. primeros bytes de `SHA256(pk)`)
en **ambos** dispositivos durante el emparejamiento.

**BL-4 (BAJA, mejorada). PIN de 6 dígitos con borrado a los 3 fallos.**
Ahora hay límite duro (3 fallos borran `sk`), lo cual da el "tiempo de margen"
pedido. Pero no hay espera entre intentos (solo ~1 s por PBKDF2), y el borrado es
destructivo (obliga a re-migrar). Aceptable; documentar.

**BL-8 (BAJA, inherente). El Core2 ve la maestra `M` en RAM un instante.**
Es la consecuencia de que el Core2 sea quien descifra. No se puede evitar en este
modelo; `M` se limpia de RAM del Core2 inmediatamente tras devolverla.

**BL-9 (INFO). Ventana de `sk` en claro antes de fijar el PIN.**
Durante la primera migración, `sk` está en `kpriv` (NVS) en claro hasta que el PIN
se fija y se borra. En esa ventana aún no hay ningún vault envuelto, así que no hay
nada que descifrar. Impacto menor.

**BL-10 (INFO). `pk` en claro (NVS del M5Paper).**
`pk` es pública por diseño; no revela nada. Solo privacidad de metadatos (vaultId,
etiqueta en el `.k2f`).

### 7.2 Verificado correcto

- **El desbloqueo autentica al Core2 criptográficamente**: el round-trip ECIES solo
  lo completa quien posee `sk` (descifra el blob y deriva la clave de sesión correcta).
- El M5Paper **no tiene la clave de descifrado**: solo guarda `pk` (pública). Robar el
  M5Paper solo no revela nada (BL-5 del diseño anterior queda **resuelto**).
- `sk` se guarda cifrada en reposo (`ksk` = `salt ‖ nonce ‖ AES-GCM(sk, PBKDF2(PIN)) ‖ tag`).
- `M` **nunca viaja en claro**: la respuesta va cifrada con `K_sess = ECDH(sk, E_sess)`
  (clave de sesión fresca por desbloqueo).
- Separación de dominio en el KDF (`m5-vault-ecies-v1`, `m5-vault-session-v1`).
- `kPinIterations` constante (150k, no se lee del archivo) → evita el DoS de S-3.
- 3 PINs fallidos → `eraseEncryptedSk()` (tiempo de margen ante robo de ambos).
- `wipe()` sobre buffers sensibles (`K_pin`, `sk` tras descifrar, `M` en el Core2,
  `master_` en el cliente).
- Tras migrar/desbloquear se limpia el estado de sesión del M5Paper.

### 7.3 Conclusión

El modelo asimétrico es estructuralmente más seguro que el anterior: el Core2 pasa a
ser una llave real (guarda la privada, descifra bajo demanda) y el M5Paper deja de
almacenar material de descifrado. Los hallazgos restantes son de endurecimiento:
blinding ECC (BL-2), PIN más largo (BL-1), confirmación visual anti-MITM (BL-3) y,
si se quiere "cifrado en reposo" de verdad, Flash Encryption del ESP32. Ninguno es
bloqueante para un prototipo "sin fondos reales".
