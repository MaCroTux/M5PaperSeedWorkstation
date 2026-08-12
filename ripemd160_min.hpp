#pragma once
#include <Arduino.h>

namespace ripemd160_min {
inline uint32_t rol(uint32_t x, uint8_t n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t f(uint8_t j, uint32_t x, uint32_t y, uint32_t z) {
  if (j < 16) return x ^ y ^ z;
  if (j < 32) return (x & y) | (~x & z);
  if (j < 48) return (x | ~y) ^ z;
  if (j < 64) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}
inline void hash(const uint8_t* data, size_t len, uint8_t out[20]) {
  static const uint8_t r[80] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
  static const uint8_t rr[80] = {5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
  static const uint8_t s[80] = {11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
  static const uint8_t ss[80] = {8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
  uint32_t h[5] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
  const size_t total = ((len + 9 + 63) / 64) * 64;
  for (size_t off = 0; off < total; off += 64) {
    uint8_t block[64] = {};
    for (size_t i = 0; i < 64 && off + i < len; ++i) block[i] = data[off + i];
    if (off <= len && len < off + 64) block[len - off] = 0x80;
    if (off + 64 == total) {
      const uint64_t bits = static_cast<uint64_t>(len) * 8;
      for (uint8_t i = 0; i < 8; ++i) block[56 + i] = bits >> (8 * i);
    }
    uint32_t x[16];
    for (uint8_t i = 0; i < 16; ++i) x[i] = block[i*4] | (uint32_t(block[i*4+1])<<8) | (uint32_t(block[i*4+2])<<16) | (uint32_t(block[i*4+3])<<24);
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4], aa=a,bb=b,cc=c,dd=d,ee=e;
    for (uint8_t j=0;j<80;++j) {
      static const uint32_t k[5]={0,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
      static const uint32_t kk[5]={0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0};
      uint32_t t=rol(a+f(j,b,c,d)+x[r[j]]+k[j/16],s[j])+e; a=e;e=d;d=rol(c,10);c=b;b=t;
      t=rol(aa+f(79-j,bb,cc,dd)+x[rr[j]]+kk[j/16],ss[j])+ee; aa=ee;ee=dd;dd=rol(cc,10);cc=bb;bb=t;
    }
    uint32_t t=h[1]+c+dd; h[1]=h[2]+d+ee; h[2]=h[3]+e+aa; h[3]=h[4]+a+bb; h[4]=h[0]+b+cc; h[0]=t;
  }
  for (uint8_t i=0;i<5;++i) for(uint8_t j=0;j<4;++j) out[i*4+j]=h[i]>>(8*j);
}
}  // namespace ripemd160_min
