#include "merkle.h"
#include "hash.h"
#include <string.h>
#include <stdlib.h>

void merkle_root(const uint8_t *leaves, size_t leaf_count, uint8_t *out) {
    if (leaf_count == 1) {
        memcpy(out, leaves, HASH_SIZE);
        return;
    }

    size_t half = leaf_count / 2;
    uint8_t left[HASH_SIZE], right[HASH_SIZE], combined[2 * HASH_SIZE];

    merkle_root(leaves, half, left);
    merkle_root(leaves + half * HASH_SIZE, half, right);

    memcpy(combined, left, HASH_SIZE);
    memcpy(combined + HASH_SIZE, right, HASH_SIZE);
    hash_sha256(combined, 2 * HASH_SIZE, out);
}
