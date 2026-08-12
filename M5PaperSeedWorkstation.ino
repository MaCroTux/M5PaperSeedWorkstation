#include <Arduino.h>

#ifdef LEGACY_M5GFX_BUILD

#ifndef ARDUINO_M5STACK_PAPER
#define ARDUINO_M5STACK_PAPER
#endif

#include <Arduino.h>
#include <M5Unified.h>
#include <SPI.h>  // Fuerza el enlace SPI en Arduino IDE 1.8.x para M5GFX.
#include "seedqr_qrcode.h"

#include "bip39_support.hpp"
 
void setup();
void loop();

namespace {

constexpr char kFirmwareVersion[] = "phase2-partial-refresh-2";
constexpr int kScreenWidth = 540;
constexpr int kScreenHeight = 960;
constexpr int kRockerRightPin = 37;
constexpr int kRockerPressPin = 38;
constexpr int kRockerLeftPin = 39;

enum class Screen { menu, length, keyboard, review, seedqr, diagnostics };

struct Rect {
  int x;
  int y;
  int w;
  int h;

  bool contains(int px, int py) const {
    return px >= x && px < x + w && py >= y && py < y + h;
  }
};

Screen current_screen = Screen::menu;
uint16_t word_indices[24];
String current_word;
uint8_t target_word_count = 12;
uint8_t word_index = 0;
bool sd_ready = false;
bool bip39_ready = false;
uint8_t focus_index = 0;
uint8_t seedqr_row = 0;
QRCode seedqr;
uint8_t seedqr_buffer[128] = {};

constexpr Rect kMenuEnter{40, 245, 460, 105};
constexpr Rect kMenuGenerate{40, 385, 460, 105};
constexpr Rect kMenuDiagnostics{40, 525, 460, 105};
constexpr Rect kChoose12{40, 260, 210, 150};
constexpr Rect kChoose24{290, 260, 210, 150};
constexpr Rect kBack{20, 850, 145, 100};
constexpr Rect kReview{190, 850, 330, 100};
constexpr Rect kQrPrevious{20, 850, 145, 100};
constexpr Rect kQrBack{190, 850, 160, 100};
constexpr Rect kQrNext{375, 850, 145, 100};
constexpr Rect kDiagnosticsBack{20, 700, 500, 230};

void begin_page(bool fast = false) {
  M5.Display.waitDisplay();
  M5.Display.setEpdMode(fast ? m5gfx::epd_fastest : m5gfx::epd_fast);
  M5.Display.fillScreen(TFT_WHITE);
  M5.Display.setTextColor(TFT_BLACK, TFT_WHITE);
  M5.Display.setTextDatum(top_left);
  M5.Display.setFont(&fonts::Font2);
  M5.Display.setTextSize(1);
}

void end_page() {
  M5.Display.display();
}

void update_region(const Rect& rect, int margin = 2) {
  const int x = max(0, rect.x - margin);
  const int y = max(0, rect.y - margin);
  const int right = min(kScreenWidth, rect.x + rect.w + margin);
  const int bottom = min(kScreenHeight, rect.y + rect.h + margin);
  M5.Display.display(x, y, right - x, bottom - y);
}

void draw_button(const Rect& rect, const char* label, bool enabled = true,
                 bool selected = false) {
  auto& d = M5.Display;
  // Interfaz 1-bit: blanco, negro y ningun sombreado. En e-ink los tramados y
  // grises ralentizan el refresco y aumentan el ghosting.
  // Es imprescindible borrar primero: una actualizacion parcial debe eliminar
  // tambien el fondo negro del foco anterior.
  d.fillRoundRect(rect.x, rect.y, rect.w, rect.h, 10, TFT_WHITE);
  if (selected && enabled) {
    d.fillRoundRect(rect.x, rect.y, rect.w, rect.h, 10, TFT_BLACK);
  }
  d.drawRoundRect(rect.x, rect.y, rect.w, rect.h, 10, TFT_BLACK);
  d.setTextColor(selected && enabled ? TFT_WHITE : TFT_BLACK,
                 selected && enabled ? TFT_BLACK : TFT_WHITE);
  d.setFont(&fonts::Font2);
  d.setTextSize(2);
  d.setTextDatum(middle_center);
  d.drawString(label, rect.x + rect.w / 2, rect.y + rect.h / 2);
  d.setTextSize(1);
  d.setTextDatum(top_left);
  d.setTextColor(TFT_BLACK, TFT_WHITE);
}

void draw_title(const char* title, const char* subtitle) {
  auto& d = M5.Display;
  d.setTextSize(3);
  d.setCursor(20, 20);
  d.println(title);
  d.setTextSize(2);
  d.setCursor(20, 86);
  d.println(subtitle);
  d.drawFastHLine(20, 140, kScreenWidth - 40, TFT_BLACK);
}

void draw_menu() {
  begin_page();
  draw_title("SEED WORKSTATION", "Prototipo offline para M5Paper");
  M5.Display.setTextSize(2);
  M5.Display.setCursor(20, 165);
  M5.Display.printf("Firmware: %s", kFirmwareVersion);
  draw_button(kMenuEnter, "INTRODUCIR SEMILLA", true, focus_index == 0);
  draw_button(kMenuGenerate, "GENERAR ENTROPIA", false);
  draw_button(kMenuDiagnostics, "DIAGNOSTICO", true, focus_index == 2);
  M5.Display.setCursor(34, 700);
  M5.Display.println("SOLO DATOS DE PRUEBA");
  M5.Display.setCursor(34, 750);
  M5.Display.println("NO USAR FONDOS REALES");
  end_page();
}

void reset_phrase(uint8_t count) {
  target_word_count = count;
  word_index = 0;
  current_word = "";
  for (auto& index : word_indices) {
    index = bip39::kInvalidWord;
  }
}

void draw_length_selector() {
  begin_page();
  draw_title("LONGITUD", "Elige 12 o 24 palabras");
  draw_button(kChoose12, "12 PALABRAS", true, focus_index == 0);
  draw_button(kChoose24, "24 PALABRAS", true, focus_index == 1);
  draw_button(kBack, "VOLVER", true, focus_index == 2);
  end_page();
}

struct KeyRow {
  const char* letters;
  int x;
  int y;
  int key_width;
};

constexpr KeyRow kRows[] = {
    {"QWERTYUIOP", 10, 265, 52},
    {"ASDFGHJKL", 34, 345, 52},
    {"ZXCVBNM", 60, 425, 60},
};

void draw_keyboard_static() {
  for (const auto& row : kRows) {
    for (size_t i = 0; row.letters[i] != '\0'; ++i) {
      Rect key{row.x + static_cast<int>(i) * row.key_width, row.y,
               row.key_width - 4, 64};
      char label[2] = {row.letters[i], '\0'};
      String candidate = current_word;
      candidate += static_cast<char>(tolower(row.letters[i]));
      draw_button(key, label, bip39::has_prefix(candidate));
    }
  }
  draw_button(Rect{20, 510, 145, 70}, "BORRAR");
  draw_button(Rect{185, 510, 335, 70}, "ANADIR PALABRA");
  draw_button(kBack, "VOLVER", true, focus_index == 0);
  draw_button(kReview, "REVISAR", true, focus_index == 1);
}

void draw_word_status(bool full_page) {
  auto& d = M5.Display;
  if (full_page) {
    begin_page(true);
    draw_title("TECLADO BIP39", "Entrada BIP39 inglesa");
    draw_keyboard_static();
  } else {
    d.waitDisplay();
    d.setEpdMode(m5gfx::epd_fast);
    d.fillRect(15, 135, 510, 115, TFT_WHITE);
  }

  d.setTextDatum(top_left);
  d.setTextColor(TFT_BLACK, TFT_WHITE);
  d.setFont(&fonts::Font2);
  d.setTextSize(2);
  d.setCursor(20, 145);
  d.printf("Palabra %u de %u", word_index + 1, target_word_count);
  d.drawRoundRect(20, 195, 500, 58, 8, TFT_BLACK);
  d.setTextSize(3);
  d.setCursor(34, 198);
  d.print(current_word.length() ? current_word : "_");

  d.setTextSize(2);
  d.fillRect(20, 600, 500, 245, TFT_WHITE);
  d.setCursor(20, 605);
  uint16_t matches[2] = {};
  const size_t match_count = bip39::find_matches(current_word, matches, 2);
  d.printf("Sugerencias: %u", static_cast<unsigned>(match_count));
  int suggestion_y = 645;
  for (size_t i = 0; i < min(match_count, static_cast<size_t>(2)); ++i) {
    d.setCursor(35, suggestion_y);
    d.print(bip39::word_at(matches[i]));
    suggestion_y += 38;
  }
  d.setCursor(20, 730);
  d.println("Anteriores:");
  const int first = max(0, static_cast<int>(word_index) - 2);
  int y = 770;
  for (int i = first; i < word_index; ++i) {
    d.setCursor(25, y);
    d.printf("%02d  %s", i + 1, bip39::word_at(word_indices[i]));
    y += 38;
  }
  if (full_page) {
    d.display();
  } else {
    // M5GFX permite enviar solamente las zonas modificadas al IT8951.
    d.display(15, 135, 510, 120);
    d.display(15, 600, 510, 245);
  }
}

void draw_review() {
  begin_page();
  draw_title("REVISION", "Palabras capturadas (sin validar)");
  M5.Display.setTextSize(2);
  int y = 145;
  for (int i = 0; i < target_word_count; ++i) {
    const int column = i >= 12 ? 1 : 0;
    const int row = i % 12;
    const int x = column == 0 ? 20 : 285;
    if (target_word_count == 24) {
      y = 145 + row * 53;
    } else {
      y = 145 + row * 53;
    }
    M5.Display.setCursor(x, y);
    M5.Display.printf("%02d %-12s", i + 1,
                      bip39::word_at(word_indices[i]));
  }
  M5.Display.setCursor(20, 805);
  if (word_index == target_word_count) {
    M5.Display.printf("Checksum BIP39: %s",
                      bip39::checksum_valid(word_indices, target_word_count)
                          ? "VALIDO"
                          : "INVALIDO");
  } else {
    M5.Display.println("Frase incompleta");
  }
  const bool valid = word_index == target_word_count &&
                     bip39::checksum_valid(word_indices, target_word_count);
  draw_button(kBack, "TECLADO", true, focus_index == 0);
  draw_button(kReview, "ABRIR SEEDQR", valid, focus_index == 1);
  end_page();
}

bool build_seedqr() {
  if (!bip39::checksum_valid(word_indices, target_word_count)) {
    return false;
  }

  char payload[97] = {};
  for (uint8_t i = 0; i < target_word_count; ++i) {
    const uint16_t value = word_indices[i];
    payload[i * 4] = '0' + (value / 1000) % 10;
    payload[i * 4 + 1] = '0' + (value / 100) % 10;
    payload[i * 4 + 2] = '0' + (value / 10) % 10;
    payload[i * 4 + 3] = '0' + value % 10;
  }
  payload[target_word_count * 4] = '\0';

  const uint8_t version = target_word_count == 12 ? 2 : 3;
  return qrcode_initText(&seedqr, seedqr_buffer, version, ECC_LOW, payload) == 0;
}

void draw_seedqr() {
  begin_page();
  draw_title("SEEDQR", "Guia fila a fila");

  const int module_size = seedqr.size == 25 ? 15 : 13;
  const int qr_pixels = seedqr.size * module_size;
  const int origin_x = (kScreenWidth - qr_pixels) / 2;
  const int origin_y = 165;

  for (uint8_t y = 0; y < seedqr.size; ++y) {
    for (uint8_t x = 0; x < seedqr.size; ++x) {
      if (qrcode_getModule(&seedqr, x, y)) {
        M5.Display.fillRect(origin_x + x * module_size,
                            origin_y + y * module_size,
                            module_size, module_size, TFT_BLACK);
      }
    }
  }

  // Flechas exteriores: resaltan la fila sin alterar ningun modulo del QR.
  const int row_y = origin_y + seedqr_row * module_size + module_size / 2;
  M5.Display.fillTriangle(origin_x - 18, row_y, origin_x - 4, row_y - 8,
                          origin_x - 4, row_y + 8, TFT_BLACK);
  M5.Display.fillTriangle(origin_x + qr_pixels + 18, row_y,
                          origin_x + qr_pixels + 4, row_y - 8,
                          origin_x + qr_pixels + 4, row_y + 8, TFT_BLACK);

  M5.Display.setTextSize(2);
  M5.Display.setCursor(20, 565);
  M5.Display.printf("FILA %02u / %02u", seedqr_row + 1, seedqr.size);

  // Copia ampliada de una sola fila para facilitar el marcado manual.
  const int zoom_size = seedqr.size == 25 ? 19 : 16;
  const int zoom_width = seedqr.size * zoom_size;
  const int zoom_x = (kScreenWidth - zoom_width) / 2;
  const int zoom_y = 635;
  for (uint8_t x = 0; x < seedqr.size; ++x) {
    const int cell_x = zoom_x + x * zoom_size;
    if (qrcode_getModule(&seedqr, x, seedqr_row)) {
      M5.Display.fillRect(cell_x, zoom_y, zoom_size, zoom_size, TFT_BLACK);
    } else {
      M5.Display.drawRect(cell_x, zoom_y, zoom_size, zoom_size, TFT_BLACK);
    }
  }
  M5.Display.setTextSize(2);
  M5.Display.setCursor(20, 705);
  M5.Display.println("Negro = marcar");
  M5.Display.setCursor(20, 750);
  M5.Display.println("Blanco = dejar vacio");

  draw_button(kQrPrevious, "ANTERIOR", seedqr_row > 0,
              focus_index == 0);
  draw_button(kQrBack, "SALIR", true, focus_index == 1);
  draw_button(kQrNext, "SIGUIENTE", seedqr_row + 1 < seedqr.size,
              focus_index == 2);
  end_page();
}

void draw_diagnostics() {
  begin_page();
  draw_title("DIAGNOSTICO", "Hardware detectado");
  M5.Display.setTextSize(2);
  M5.Display.setCursor(25, 165);
  M5.Display.printf("Placa: %s\n\n",
                    M5.getBoard() == m5::board_t::board_M5Paper ? "M5Paper" : "NO");
  M5.Display.printf("Pantalla: %d x %d\n\n", M5.Display.width(),
                    M5.Display.height());
  M5.Display.printf("Tactil: %s\n\n", M5.Touch.isEnabled() ? "OK" : "NO");
  M5.Display.printf("microSD: %s\n\n", sd_ready ? "OK" : "NO");
  M5.Display.printf("PSRAM: %u KB", ESP.getPsramSize() / 1024U);
  M5.Display.printf("\n\nBIP39: %s", bip39_ready ? "OK" : "ERROR");
  draw_button(kDiagnosticsBack, "VOLVER AL MENU", true, true);
  end_page();
}

char key_at(int x, int y) {
  for (const auto& row : kRows) {
    if (y < row.y || y >= row.y + 64) {
      continue;
    }
    const int index = (x - row.x) / row.key_width;
    if (x >= row.x && index >= 0 &&
        index < static_cast<int>(strlen(row.letters))) {
      return static_cast<char>(tolower(row.letters[index]));
    }
  }
  return '\0';
}

void handle_keyboard(int x, int y) {
  const char key = key_at(x, y);
  if (key && current_word.length() < 12) {
    String candidate = current_word;
    candidate += key;
    if (bip39::has_prefix(candidate)) {
      current_word = candidate;
      Serial.printf("BIP39 input: %s\n", current_word.c_str());
      // No redibujar el teclado completo: el IT8951 bloquea durante el
      // refresco y se perderian pulsaciones posteriores.
      draw_word_status(false);
    } else {
      Serial.printf("BIP39 rejected prefix: %s\n", candidate.c_str());
    }
    return;
  }

  if (Rect{20, 510, 145, 70}.contains(x, y)) {
    if (current_word.length()) {
      current_word.remove(current_word.length() - 1);
      draw_word_status(false);
    }
    return;
  }

  if (Rect{185, 510, 335, 70}.contains(x, y)) {
    uint16_t selected = bip39::find_exact(current_word);
    uint16_t matches[1] = {};
    const size_t match_count = bip39::find_matches(current_word, matches, 1);
    if (selected == bip39::kInvalidWord && match_count == 1) {
      selected = matches[0];
    }
    if (selected != bip39::kInvalidWord && word_index < target_word_count) {
      word_indices[word_index++] = selected;
      current_word = "";
      if (word_index == target_word_count) {
        current_screen = Screen::review;
        draw_review();
      } else {
        draw_word_status(false);
      }
    } else {
      Serial.printf("BIP39 word not complete: %s\n", current_word.c_str());
    }
    return;
  }

  if (kBack.contains(x, y)) {
    current_screen = Screen::menu;
    draw_menu();
  } else if (kReview.contains(x, y)) {
    current_screen = Screen::review;
    draw_review();
  }
}

void handle_click(int x, int y) {
  switch (current_screen) {
    case Screen::menu:
      if (kMenuEnter.contains(x, y)) {
        focus_index = 0;
        current_screen = Screen::length;
        draw_length_selector();
      } else if (kMenuDiagnostics.contains(x, y)) {
        focus_index = 0;
        current_screen = Screen::diagnostics;
        draw_diagnostics();
      }
      break;

    case Screen::length:
      if (kChoose12.contains(x, y) || kChoose24.contains(x, y)) {
        reset_phrase(kChoose12.contains(x, y) ? 12 : 24);
        focus_index = 0;
        current_screen = Screen::keyboard;
        draw_word_status(true);
      } else if (kBack.contains(x, y)) {
        current_screen = Screen::menu;
        focus_index = 0;
        draw_menu();
      }
      break;

    case Screen::keyboard:
      handle_keyboard(x, y);
      break;

    case Screen::review:
      if (kBack.contains(x, y)) {
        current_screen = Screen::keyboard;
        focus_index = 0;
        draw_word_status(true);
      } else if (kReview.contains(x, y) && build_seedqr()) {
        seedqr_row = 0;
        focus_index = 2;
        current_screen = Screen::seedqr;
        draw_seedqr();
      }
      break;

    case Screen::seedqr:
      if (kQrPrevious.contains(x, y) && seedqr_row > 0) {
        --seedqr_row;
        draw_seedqr();
      } else if (kQrNext.contains(x, y) && seedqr_row + 1 < seedqr.size) {
        ++seedqr_row;
        draw_seedqr();
      } else if (kQrBack.contains(x, y)) {
        focus_index = 1;
        current_screen = Screen::review;
        draw_review();
      }
      break;

    case Screen::diagnostics:
      // La mitad inferior completa actua como salida. En una pantalla con una
      // sola accion no tiene sentido exigir acertar un boton pequeno.
      if (y >= 620) {
        current_screen = Screen::menu;
        focus_index = 0;
        draw_menu();
      }
      break;
  }
}

void redraw_current_screen() {
  switch (current_screen) {
    case Screen::menu: draw_menu(); break;
    case Screen::length: draw_length_selector(); break;
    case Screen::keyboard: draw_word_status(true); break;
    case Screen::review: draw_review(); break;
    case Screen::seedqr: draw_seedqr(); break;
    case Screen::diagnostics: draw_diagnostics(); break;
  }
}

void redraw_focus_controls(uint8_t previous_focus) {
  auto& d = M5.Display;
  d.waitDisplay();
  d.setEpdMode(m5gfx::epd_fastest);

  auto update_button = [&](const Rect& rect, const char* label, bool enabled,
                           uint8_t index) {
    if (index != previous_focus && index != focus_index) return;
    draw_button(rect, label, enabled, focus_index == index);
    update_region(rect);
  };

  switch (current_screen) {
    case Screen::menu:
      update_button(kMenuEnter, "INTRODUCIR SEMILLA", true, 0);
      update_button(kMenuDiagnostics, "DIAGNOSTICO", true, 2);
      break;
    case Screen::length:
      update_button(kChoose12, "12 PALABRAS", true, 0);
      update_button(kChoose24, "24 PALABRAS", true, 1);
      update_button(kBack, "VOLVER", true, 2);
      break;
    case Screen::keyboard:
      update_button(kBack, "VOLVER", true, 0);
      update_button(kReview, "REVISAR", true, 1);
      break;
    case Screen::review: {
      const bool valid = word_index == target_word_count &&
                         bip39::checksum_valid(word_indices, target_word_count);
      update_button(kBack, "TECLADO", true, 0);
      update_button(kReview, "ABRIR SEEDQR", valid, 1);
      break;
    }
    case Screen::seedqr:
      update_button(kQrPrevious, "ANTERIOR", seedqr_row > 0, 0);
      update_button(kQrBack, "SALIR", true, 1);
      update_button(kQrNext, "SIGUIENTE", seedqr_row + 1 < seedqr.size, 2);
      break;
    case Screen::diagnostics:
      break;
  }
}

void move_focus(int direction) {
  const uint8_t previous_focus = focus_index;
  switch (current_screen) {
    case Screen::menu:
      // La opcion 1 (generar entropia) aun esta deshabilitada.
      focus_index = focus_index == 0 ? 2 : 0;
      break;
    case Screen::length:
      focus_index = static_cast<uint8_t>((focus_index + direction + 3) % 3);
      break;
    case Screen::keyboard:
      // La escritura es tactil; la ruleta alterna Volver/Revisar.
      focus_index = focus_index == 0 ? 1 : 0;
      break;
    case Screen::review:
      focus_index = focus_index == 0 ? 1 : 0;
      break;
    case Screen::seedqr:
      focus_index = static_cast<uint8_t>((focus_index + direction + 3) % 3);
      break;
    case Screen::diagnostics:
      focus_index = 0;
      break;
  }
  // No reconstruir la pagina completa por cada paso de la ruleta.
  redraw_focus_controls(previous_focus);
}

void activate_focus() {
  switch (current_screen) {
    case Screen::menu:
      handle_click(focus_index == 0 ? kMenuEnter.x + 10 : kMenuDiagnostics.x + 10,
                   focus_index == 0 ? kMenuEnter.y + 10 : kMenuDiagnostics.y + 10);
      break;
    case Screen::length:
      if (focus_index == 0) handle_click(kChoose12.x + 10, kChoose12.y + 10);
      else if (focus_index == 1) handle_click(kChoose24.x + 10, kChoose24.y + 10);
      else handle_click(kBack.x + 10, kBack.y + 10);
      break;
    case Screen::keyboard:
      handle_click(focus_index == 0 ? kBack.x + 10 : kReview.x + 10,
                   focus_index == 0 ? kBack.y + 10 : kReview.y + 10);
      break;
    case Screen::review:
      handle_click(focus_index == 0 ? kBack.x + 10 : kReview.x + 10,
                   focus_index == 0 ? kBack.y + 10 : kReview.y + 10);
      break;
    case Screen::seedqr:
      if (focus_index == 0) handle_click(kQrPrevious.x + 10, kQrPrevious.y + 10);
      else if (focus_index == 1) handle_click(kQrBack.x + 10, kQrBack.y + 10);
      else handle_click(kQrNext.x + 10, kQrNext.y + 10);
      break;
    case Screen::diagnostics:
      handle_click(kDiagnosticsBack.x + 10, kDiagnosticsBack.y + 10);
      break;
  }
}

}  // namespace

void setup() {
  auto config = M5.config();
  config.serial_baudrate = 115200;
  config.clear_display = true;
  config.output_power = true;
  config.internal_imu = false;
  config.internal_mic = false;
  config.internal_spk = false;
  config.internal_rtc = true;
  config.external_display_value = 0;
  config.fallback_board = m5::board_t::board_M5Paper;
  M5.begin(config);

  // Lectura directa para que la palanca funcione incluso cuando Arduino IDE
  // obliga a compilar con una definicion antigua como M5Stack-FIRE.
  pinMode(kRockerLeftPin, INPUT);
  pinMode(kRockerPressPin, INPUT);
  pinMode(kRockerRightPin, INPUT);

  M5.Display.setRotation(0);
  Serial.printf("\nM5Paper Seed Workstation - %s\n", kFirmwareVersion);
  Serial.printf("Board=%d Display=%dx%d Touch=%s\n",
                static_cast<int>(M5.getBoard()), M5.Display.width(),
                M5.Display.height(), M5.Touch.isEnabled() ? "si" : "no");

  bip39_ready = bip39::self_test();
  Serial.printf("BIP39 self-test: %s\n", bip39_ready ? "OK" : "ERROR");

  draw_menu();

  // La pantalla IT8951 y la microSD comparten SCLK/MISO/MOSI. Crear aquí una
  // segunda instancia HSPI deja visible el primer frame pero impide todos los
  // refrescos posteriores. La SD permanece desactivada hasta implementar una
  // capa de bus compartido que libere correctamente cada dispositivo.
  sd_ready = false;
}

void loop() {
  M5.update();

  static int previous_left = HIGH;
  static int previous_press = HIGH;
  static int previous_right = HIGH;
  static uint32_t last_rocker_ms = 0;
  const int left = digitalRead(kRockerLeftPin);
  const int press = digitalRead(kRockerPressPin);
  const int right = digitalRead(kRockerRightPin);
  if (millis() - last_rocker_ms >= 180) {
    if (left == LOW && previous_left == HIGH) {
      last_rocker_ms = millis();
      Serial.println("Rocker: izquierda");
      move_focus(-1);
    } else if (right == LOW && previous_right == HIGH) {
      last_rocker_ms = millis();
      Serial.println("Rocker: derecha");
      move_focus(1);
    } else if (press == LOW && previous_press == HIGH) {
      last_rocker_ms = millis();
      Serial.println("Rocker: pulsacion");
      activate_focus();
    }
  }
  previous_left = left;
  previous_press = press;
  previous_right = right;

  const auto count = M5.Touch.getCount();
  static uint32_t last_touch_ms = 0;
  for (size_t i = 0; i < count; ++i) {
    const auto touch = M5.Touch.getDetail(i);
    // EPDGUI activa controles al comenzar/soltar la pulsacion. En esta interfaz
    // usamos wasPressed para no exigir un click perfectamente inmovil.
    if (touch.wasPressed() && millis() - last_touch_ms >= 220) {
      last_touch_ms = millis();
      Serial.printf("Touch: x=%d y=%d screen=%d\n", touch.x, touch.y,
                    static_cast<int>(current_screen));
      handle_click(touch.x, touch.y);
      break;
    }
  }
  M5.delay(16);
}

#endif  // LEGACY_M5GFX_BUILD
