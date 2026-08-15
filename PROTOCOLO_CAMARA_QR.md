# PROTOCOLO BLE — Cámara QR externa (ESP32-CAM + OV2640)

El M5Paper usa un módulo ESP32-CAM como **coprocesador de visión**: la cámara lee
un QR, lo decodifica y envía el payload **ya decodificado** (opaco) por BLE. El
M5Paper **no recibe imágenes**, solo el contenido del QR.

> **Estado: protocolo V1 experimental.** No congelar para producción sin añadir
> (mínimo): versión de protocolo, transfer ID, tipo de mensaje, checksum/hash del
> payload, ACK/NACK, cancelación y negociación de MTU.

## 1. Roles BLE

| Dispositivo | Rol BLE | Rol funcional |
|---|---|---|
| ESP32-CAM | Peripheral / GATT Server | Anuncia, decodifica QR, envía payload |
| M5Paper | Central / GATT Client | Escanea, conecta, suscribe, reconstruye |

## 2. Identificadores BLE

| Elemento | Valor |
|---|---|
| Nombre del dispositivo | `M5Paper-QR-CAM` |
| Service UUID | `6E400001-B5A3-F393-E0A9-E50E24DCCA9E` |
| `RX` (WRITE) — M5Paper → cámara | `6E400002-B5A3-F393-E0A9-E50E24DCCA9E` |
| `TX` (NOTIFY) — cámara → M5Paper | `6E400003-B5A3-F393-E0A9-E50E24DCCA9E` |

Protocolo inspirado en Nordic UART Service.

## 3. Características

### 3.1 `RX` — WRITE (comandos M5Paper → cámara)

Comandos iniciales:

| Comando | Respuesta esperada |
|---|---|
| `PING` | `PONG` |
| `STATUS` | `SCANNING` |

El M5Paper envía `STATUS` tras suscribirse a `TX`.

### 3.2 `TX` — NOTIFY (cámara → M5Paper)

El M5Paper **debe suscribirse** a esta característica. Por ella llegan, como
líneas de texto terminadas en `\n`:

- `PONG` — respuesta a `PING`.
- `SCANNING` — la cámara está escaneando.
- `QRBEGIN:<size>:<chunks>` — inicio de transferencia.
- `<index>:<data>` — un fragmento del payload.
- `QREND` — fin de transferencia.

## 4. Transferencia QR (fragmentada)

Ejemplo (PSBT en Base64 de 288 bytes, 16 chunks de 18 bytes):

```
QRBEGIN:288:16
0:cHNidP8BAF4CAAAA
1:ARPjQwAujUBNYPl0
2:j+z6qK79XFJipNYG
...
QREND
```

Reglas:

- **Cada notificación debe terminar en `\n`** (incluidos `QRBEGIN`, cada chunk
  y `QREND`). El M5Paper reconstruye el stream dividiendo por `\n`; si el
  emisor no lo añade, dos notificaciones consecutivas se concatenan y se
  parsean mal (`QR_TRANSFER_ERROR`, `overlap`). Los comandos `PONG`/`SCANNING`
  también van terminados en `\n`.
- `size` = tamaño total en bytes del payload reconstruido.
- `chunks` = número de fragmentos.
- `<index>` = índice decimal desde `0` hasta `chunks-1`.
- `<data>` = **substring crudo del payload** (bytes opacos, NO hex), de hasta
  18–20 bytes por notificación según MTU. La cámara decide el tamaño de cada
  fragmento; el último puede ser más corto.

## 5. Reconstrucción en el M5Paper

Al recibir `QRBEGIN` se crea un contexto de transferencia:

- `expectedSize`, `expectedChunks`, buffer por índice, `startTime`.

Cada `<index>:<data>` se guarda **por índice** (no se asume orden ni que recibir
`QREND` garantice integridad). Al recibir `QREND`:

1. verificar que todos los índices `0..chunks-1` están presentes;
2. concatenar por índice;
3. verificar `reconstructed.size() == expectedSize`;
4. si correcto → entregar el payload al QR dispatcher del M5Paper;
5. destruir el contexto.

Si `reconstructed.size() != expectedSize` → `QR_TRANSFER_ERROR`.

## 6. Límites y timeout (M5Paper)

| Parámetro | Valor |
|---|---|
| `MAX_QR_PAYLOAD` | 32768 bytes |
| `MAX_QR_CHUNKS` | 1024 |
| Timeout de transferencia | 30000 ms |

Antes de reservar memoria se valida: `size > 0`, `size <= MAX_QR_PAYLOAD`,
`chunks > 0`, `chunks <= MAX_QR_CHUNKS`. Si `QRBEGIN` no cumple → error. Si la
transferencia no termina en 30 s → cancelar, liberar buffer, mostrar/reintentar.

## 7. Payload opaco y seguridad

La cámara **NO** interpreta Bitcoin: trata el contenido como **datos opacos**.
Ejemplos posibles: dirección Bitcoin, PSBT Base64, fragmento BBQr, fragmento UR,
descriptor, xpub/zpub, texto.

```
OV2640 → ESP32-CAM → QR decode → payload opaco → BLE → M5Paper → QR dispatcher
                                                          → Bitcoin / PSBT / UR / BBQr / descriptor
```

La cámara es **no confiable** y **nunca** debe:

- recibir seed ni claves privadas;
- almacenar seed;
- firmar;
- interpretar o desbloquear el Vault.

**QR animados (fountain code).** Si la cámara soporta reensamblado, los QR
animados `ur:crypto-psbt/<seqnum>-<seqlen>/<part>` (BCR-2020-003, fountain
code) se reensamblan **en la cámara** y se entregan por el mismo transporte
como un payload completo (por ejemplo, un UR de una sola parte
`ur:crypto-psbt/<bytewords>` o un PSBT Base64). El M5Paper **no** hace
reensamblado de fountain codes: recibe un único payload completo.

Todo contenido recibido pasa por las mismas validaciones que un QR de cualquier
otra fuente. Nunca: `cámara → firmar` directamente. Siempre:

```
cámara → validación de transporte → QR dispatcher → parser de formato
       → validación PSBT → revisión de transacción → confirmación física → firmar
```

## 8. BLE y firma

Al recibir un PSBT completo: validar transferencia → desconectar la cámara →
BLE OFF → parsear/revisar → desbloquear Vault → firmar. **Radio OFF antes de
trabajar con claves privadas.**

## 9. Implementación de referencia (M5Paper)

- `lib/seedworkstation_core/src/qr_cam_client.hpp/.cpp` — cliente BLE.
- `NativeApp.cpp` — pantalla `scan_cam_qr` (fuente `RECIBIR → ESCANEAR QR (CAMARA)`).

Estados internos: `Off, Scanning, Connecting, Connected, WaitingQr, Receiving,
Complete, Error, Cancelled`.

## 10. Fuera de alcance (V1)

No implementar todavía en el M5Paper: ensamblado de fountain codes en el
M5Paper, fotografías, streaming, vídeo. El **reensamblado de QR animados
(fountain) se hace en la cámara**, que entrega un payload completo por el
mismo transporte (ver §7). La interfaz M5Paper permanece igual.
