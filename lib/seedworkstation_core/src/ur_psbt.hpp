#pragma once
#include <Arduino.h>
#include <vector>

// Decodificacion de UR "crypto-psbt" (Blockchain Commons / BCR-2020-002) en su
// forma de una sola parte (sin fountain codes).
//
// Pipeline: bytewords (estilo "minimal": primera+ultima letra de cada palabra)
//           -> bytes CBOR -> byte string CBOR -> PSBT (psbt\xff...).
//
// Ejemplo: ur:crypto-psbt/HKAD...  ->  CBOR 59 018b <psbt>  ->  PSBT.

namespace ur {

const char kWordlist[] =
    "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasblue"
    "bodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurl"
    "cuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasy"
    "echoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewflux"
    "foxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugush"
    "gyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinch"
    "inkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkeno"
    "keptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlist"
    "logoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonk"
    "nailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpart"
    "peckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroad"
    "rockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstub"
    "surfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundo"
    "uniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwave"
    "waxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczone"
    "zoom";

// Decodifica una palabra "minimal" (2 letras: primera+ultima) a su indice (0-255).
inline int minimalToIndex(char a, char b) {
  for (int i = 0; i < 256; ++i) {
    if (kWordlist[i * 4] == a && kWordlist[i * 4 + 3] == b) return i;
  }
  return -1;
}

inline bool decodeBytewords(const String& payload, std::vector<uint8_t>& out) {
  out.clear();
  if (payload.length() % 2 != 0) return false;
  for (size_t i = 0; i < payload.length(); i += 2) {
    const int idx = minimalToIndex(payload[i], payload[i + 1]);
    if (idx < 0) return false;
    out.push_back(static_cast<uint8_t>(idx));
  }
  return !out.empty();
}

// Desenvuelve una byte string CBOR (major type 2) y devuelve su contenido.
inline bool unwrapCborBytes(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
  out.clear();
  if (in.size() < 1) return false;
  if ((in[0] >> 5) != 2) return false;  // no es byte string
  const uint8_t info = in[0] & 0x1f;
  size_t len = 0, off = 1;
  if (info < 24) {
    len = info;
  } else if (info == 24) {
    if (in.size() < 2) return false;
    len = in[1]; off = 2;
  } else if (info == 25) {
    if (in.size() < 3) return false;
    len = (static_cast<size_t>(in[1]) << 8) | in[2]; off = 3;
  } else if (info == 26) {
    if (in.size() < 5) return false;
    len = (static_cast<size_t>(in[1]) << 24) | (static_cast<size_t>(in[2]) << 16) |
          (static_cast<size_t>(in[3]) << 8) | in[4];
    off = 5;
  } else {
    return false;
  }
  if (off + len > in.size()) return false;
  out.assign(in.begin() + off, in.begin() + off + len);
  return !out.empty();
}

// Decodifica un UR "ur:crypto-psbt/<bytewords>" a los bytes del PSBT.
inline bool decodeCryptoPsbt(const String& ur, std::vector<uint8_t>& psbtOut) {
  psbtOut.clear();
  String s = ur;
  s.toLowerCase();
  const int idx = s.indexOf("crypto-psbt/");
  if (idx < 0) return false;
  const String payload = s.substring(idx + 12);  // strlen("crypto-psbt/") = 12
  std::vector<uint8_t> cbor;
  if (!decodeBytewords(payload, cbor)) return false;
  std::vector<uint8_t> psbt;
  if (!unwrapCborBytes(cbor, psbt)) return false;
  if (psbt.size() < 5 || psbt[0] != 0x70 || psbt[1] != 0x73 ||
      psbt[2] != 0x62 || psbt[3] != 0x74) return false;
  psbtOut = psbt;
  return true;
}

}  // namespace ur
