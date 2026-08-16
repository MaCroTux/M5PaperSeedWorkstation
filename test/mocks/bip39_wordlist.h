// Definicion de bip39::g_wordlist para los tests nativos (host).
// En el firmware la define bip39_wordlist.cpp (no compilada en el entorno host).
#pragma once
#include "bip39_support.hpp"

namespace bip39 {
Wordlist g_wordlist = Wordlist::English;
}
