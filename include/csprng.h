#ifndef CSPRNG_H
#define CSPRNG_H

#include <stddef.h>
#include <stdint.h>

/* Initialize ChaCha20 CSPRNG with random OS seed or user-provided key/nonce */
void csprng_init(const uint8_t *key, const uint8_t *nonce);

/* Initialize with deterministic seed (for testing/benchmarking) */
void csprng_seed_from_int(uint64_t seed);

/* Generate `len` random bytes */
void csprng_random_bytes(uint8_t *out, size_t len);

#endif
