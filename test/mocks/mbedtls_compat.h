// Compatibilidad mbedtls 2.x -> 3.x para los tests nativos (host).
//
// SeedWorkstationCore esta escrito contra el mbedtls 2.28 del ESP32 core.
// mbedtls 3.x (brew reciente / Ubuntu 24.04) introdujo cambios incompatibles:
//   1. Renombro las funciones SHA-256 con sufijo "_ret" (la version sin sufijo
//      paso a devolver int).
//   2. Oculto los campos de las estructuras detras de MBEDTLS_PRIVATE.
//   3. mbedtls_ecp_mul() ahora exige f_rng != NULL (en 2.x podia ser NULL
//      para operar sin blinding).
//
// Todo esto se aplica SOLO a mbedtls 3.x; con mbedtls 2.x (Ubuntu 22.04) el
// core compila tal cual. Este fichero se fuerza-incluye al inicio de cada
// unidad de traduccion con `-include mbedtls_compat.h`.
#ifndef MBEDTLS_HOST_COMPAT_H
#define MBEDTLS_HOST_COMPAT_H

#include <mbedtls/version.h>

#if defined(MBEDTLS_VERSION_MAJOR) && (MBEDTLS_VERSION_MAJOR >= 3)

// Recupera el acceso a campos como mbedtls_ecp_point.X (usado por el core).
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif

// Incluye las declaraciones reales ANTES de redefinir mbedtls_ecp_mul.
#include <mbedtls/ecp.h>

// mbedtls 3.x: las funciones *_ret se eliminaron (la "sin sufijo" ya devuelve
// el codigo de error).
#define mbedtls_sha256_ret mbedtls_sha256
#define mbedtls_sha256_starts_ret mbedtls_sha256_starts
#define mbedtls_sha256_update_ret mbedtls_sha256_update
#define mbedtls_sha256_finish_ret mbedtls_sha256_finish

// RNG determinista para el blinding de mbedtls_ecp_mul cuando el core pasa
// f_rng = NULL (permitido en 2.x, rechazado en 3.x).
static unsigned long mbedtls_host_rng_state = 0x9e3779b9UL;
static int mbedtls_host_rng(void*, unsigned char* out, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    unsigned long x = mbedtls_host_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    mbedtls_host_rng_state = x;
    out[i] = (unsigned char)(x & 0xff);
  }
  return 0;
}

static inline int mbedtls_ecp_mul_host(mbedtls_ecp_group* grp, mbedtls_ecp_point* R,
                                       const mbedtls_mpi* m, const mbedtls_ecp_point* P,
                                       int (*f_rng)(void*, unsigned char*, size_t),
                                       void* p_rng) {
  return mbedtls_ecp_mul(grp, R, m, P,
                         f_rng ? f_rng : mbedtls_host_rng,
                         f_rng ? p_rng : NULL);
}

// Redirige las llamadas del core a nuestro wrapper que provee RNG por defecto.
#define mbedtls_ecp_mul(grp, R, m, P, f_rng, p_rng) \
  mbedtls_ecp_mul_host(grp, R, m, P, f_rng, p_rng)

#endif  // MBEDTLS_VERSION_MAJOR >= 3

#endif  // MBEDTLS_HOST_COMPAT_H
