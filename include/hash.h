#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_SIZE 32  // Output size for SHAKE256 (256-bit security)

// SHAKE256 hashing
void hash_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

#endif
