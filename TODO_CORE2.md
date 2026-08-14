# TODO — Soporte M5Stack Core2

Estado del port de Core2 (320×240, M5Unified/M5GFX, touch FT6336U, botones A/B/C).
La lógica Bitcoin/vault/PSBT/firma ya es **común** (`lib/seedworkstation_core/`);
aquí solo falta la **UI** de Core2.

- [x] = hecho
- [ ] = pendiente

---

## 1. Infraestructura

- [x] Boot con M5Unified + display 320×240 landscape.
- [x] Touch FT6336U.
- [x] Botones físicos A/B/C (A=atrás, B/C=contextuales) + footer de ayuda.
- [ ] **Haptic** (vibración al pulsar/confirmar/error) — `platform::haptic`.
- [ ] **SD wrapper** (`platformSDInit`) para que los formatos de vault sean idénticos al M5Paper.
- [ ] **Tema/colores**: roles accent/warning (ahora solo blanco/negro).

## 2. Semilla

- [x] Teclado BIP39 con autocompletado y salida.
- [x] Revisión paginada (8 palabras/página).
- [x] Entropía por dados (1-6, 50/100 tiradas).
- [ ] Entropía por **dibujo** (área táctil).
- [ ] **Backup**: palabras (paginado), QR, SEEDQR.
- [ ] **Passphrase BIP39**.

## 3. Vault

- [ ] Vault **individual** (`.vlt`): crear/abrir/borrar.
- [ ] Vault de **sesión** (`.svm`/`.svs`): crear/abrir/cerrar, varias semillas.
- [ ] Verificar compatibilidad SD M5Paper ↔ Core2 (mismo formato).

## 4. Derivación

- [x] Explorador de direcciones (BIP84, recibir/cambio, índice ±).
- [ ] Añadir **BIP44 / BIP49**.
- [ ] **Clave pública** (xpub/zpub).
- [ ] **QR** de dirección y de clave pública.

## 5. PSBT / firma

- [ ] **Recibir PSBT** por WiFi AP (portal cautivo) y por serial (`M5PSBT`).
- [ ] **Revisión de transacción** single-sig (PAGO/CAMBIO/COMISIÓN, direcciones).
- [ ] **Revisión multisig** (política, signers, firmas).
- [ ] **Firmar** single-sig (P2WPKH) con pantalla de feedback.
- [ ] **Firmar** multisig (P2WSH sortedmulti).
- [ ] **QR Sparrow** (hex estático).
- [ ] **QR BlueWallet** (BBQr animado).

## 6. Ajustes

- [x] Idioma EN/ES.
- [ ] Tiempo de bloqueo (1/3/5/10 min, nunca).
- [ ] Limpieza de seed (nunca/10/30/60 min).
- [ ] Derivación por defecto (BIP44/49/84).
- [ ] Estado de la radio (BT/WiFi/SD/batería).

## 7. Otros

- [ ] **Historial de transacciones** (guardar y volver a firmar).
- [ ] **Ayuda** (conceptos básicos).
- [ ] **Auto-bloqueo / screensaver** por inactividad.
- [ ] Traducciones EN/ES completas de las pantallas nuevas.

## 8. Llave BLE (M5Core2 como llave física)

- [x] Servidor GATT `M5Core2-Key` (NimBLE) con servicio "M5 Vault Key".
- [x] Pantalla `LOCKED / Waiting...` + `PAIR REQUEST [CANCEL][AUTHORIZE]`.
- [x] Identidad asimétrica: `sk` (privada, cifrada con PIN) + `pk` (pública).
- [x] Teclado de PIN en el Core2 (fijar PIN + verificar en el desbloqueo).
- [x] Desbloqueo ECIES: el Core2 descifra la maestra del vault con `sk` tras el PIN.
- [x] 3 PINs fallidos borran la clave (`sk`) del Core2.
- [x] En el M5Paper: emparejar / eliminar llave, y **desbloquear el vault de sesión con
      Core2 + PIN** (incluida la migración de vault solo-contraseña).

---

## Orden recomendado

1. Firma single-sig (recibir → revisar → firmar → QR Sparrow): es el flujo crítico.
2. Vault de sesión (reutiliza `.svm`/`.svs` del M5Paper).
3. Backup + passphrase.
4. Multisig + BBQr.
5. Ajustes completos + historial + ayuda.
6. Pulido (haptic, tema, entropía por dibujo, QR de dirección/clave).
