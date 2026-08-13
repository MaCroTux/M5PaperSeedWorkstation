#pragma once
#include <Arduino.h>

// Identificacion de plataforma y constantes por dispositivo.
//
// Seleccion por flag de compilacion (definido en platformio.ini / Arduino IDE):
//   TARGET_M5PAPER  -> M5Paper (540x960, e-ink M5EPD, GT911)
//   TARGET_M5CORE2  -> M5Stack Core2 (320x240, IPS M5GFX/M5Unified, FT6336U)
//
// Regla: la logica Bitcoin/vault/PSBT/firma es COMUN. Aqui solo vive lo que
// cambia entre dispositivos: dimensiones, tipo de color y helpers de hardware.

#if defined(TARGET_M5CORE2)
  #define PLATFORM_M5CORE2 1
  #define DEVICE_WIDTH  320
  #define DEVICE_HEIGHT 240
  using Color = uint32_t;
  constexpr Color kWhite = 0xFFFFU;   // TFT_WHITE (RGB565)
  constexpr Color kBlack = 0x0000U;   // TFT_BLACK
  constexpr Color kGray  = 0x8410U;   // gris medio (texto secundario)
#elif defined(TARGET_M5PAPER)
  #define PLATFORM_M5PAPER 1
  #define DEVICE_WIDTH  540
  #define DEVICE_HEIGHT 960
  using Color = uint8_t;
  constexpr Color kWhite = 0;
  constexpr Color kBlack = 15;
  constexpr Color kGray  = 7;         // gris medio (grayscale 4 bits)
#else
  #error "Define TARGET_M5PAPER o TARGET_M5CORE2 antes de compilar."
#endif

namespace platform {

enum class Haptic { tap, confirm, error };

inline void haptic(Haptic) {
  // M5Paper: sin actuador -> no-op.
  // M5Core2: implementar vibracion en el backend cuando se integre.
}

inline const char* name() {
#if defined(PLATFORM_M5CORE2)
  return "M5Core2";
#else
  return "M5Paper";
#endif
}

}  // namespace platform
