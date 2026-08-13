// UI del M5Stack Core2 (320x240, M5Unified/M5GFX, touch FT6336U).
//
// Comparte TODA la logica Bitcoin/vault/PSBT/firma con el M5Paper a traves de
// la libreria lib/seedworkstation_core. Aqui solo vive display, touch y
// geometria, con layouts propios (no se escala la interfaz 540x960 del M5Paper).
//
// Milestone 1: boot -> display -> touch -> menu principal.

#include <M5Unified.h>
#include "platform/platform.hpp"
#include "lang.hpp"

namespace {

struct Rect { int x, y, w, h; };

inline bool contains(const Rect& r, int x, int y) {
  return x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
}

// Menu principal: 2 columnas x 4 filas (7 acciones + ayuda).
constexpr Rect kMenu[8] = {
  {5, 30, 152, 42}, {163, 30, 152, 42},
  {5, 78, 152, 42}, {163, 78, 152, 42},
  {5, 126, 152, 42}, {163, 126, 152, 42},
  {5, 174, 152, 42}, {163, 174, 152, 42},
};
constexpr const char* kMenuKeys[8] = {
  "INTRODUCIR SEMILLA", "GENERAR ENTROPIA", "VAULT DE SESION", "RECIBIR POR WIFI",
  "HISTORIAL", "AJUSTES", "BLOQUEAR", "AYUDA",
};

int selected = -1;

void drawButton(const Rect& r, const char* label, bool sel) {
  M5.Display.fillRoundRect(r.x, r.y, r.w, r.h, 8, sel ? kBlack : kWhite);
  M5.Display.drawRoundRect(r.x, r.y, r.w, r.h, 8, kBlack);
  M5.Display.setTextColor(sel ? kWhite : kBlack, sel ? kBlack : kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(1);
  M5.Display.drawString(lang::tr(label), r.x + r.w / 2, r.y + r.h / 2);
}

void drawMenu() {
  M5.Display.fillScreen(kWhite);
  M5.Display.setTextColor(kBlack, kWhite);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(2);
  M5.Display.drawString("M5 Seed Workstation", DEVICE_WIDTH / 2, 14);
  for (int i = 0; i < 8; ++i) drawButton(kMenu[i], kMenuKeys[i], selected == i);
}

}  // namespace

void setup() {
  M5.begin();
  M5.Display.setRotation(1);
  drawMenu();
}

void loop() {
  M5.update();
  auto t = M5.Touch.getDetail();
  if (t.wasPressed()) {
    for (int i = 0; i < 8; ++i) {
      if (contains(kMenu[i], t.x, t.y)) {
        selected = i;
        drawMenu();
        break;
      }
    }
  }
}
