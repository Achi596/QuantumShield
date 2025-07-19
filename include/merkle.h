#ifndef MERKLE_H
#define MERKLE_H

#include <stdint.h>
#include "hash.h"

/**
 * Compute a Merkle root from a flat array of leaves.
 * @param leaves    Array of leaf hashes [num_leaves][HASH_SIZE]
 * @param num_leaves Power-of-two number of leaves
 * @param root      Output buffer (HASH_SIZE)
 */
void merkle_compute_root(const uint8_t leaves[][HASH_SIZE], int num_leaves, uint8_t root[HASH_SIZE]);

#endif
