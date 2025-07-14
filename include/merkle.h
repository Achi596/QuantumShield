#ifndef MERKLE_H
#define MERKLE_H

#include <stdint.h>
#include <stddef.h>
#include "hash.h"

void merkle_root(const uint8_t *leaves, size_t leaf_count, uint8_t *out);

#endif
