#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stddef.h>

#define HASH_SIZE 32

void hash_sha256(const uint8_t *input, size_t len, uint8_t *out);

#endif
