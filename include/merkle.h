#ifndef MERKLE_H
#define MERKLE_H

#include <stdint.h>
#include "hash.h"

// This header file defines functions for working with Merkle Trees.
void merkle_compute_root(const uint8_t leaves[][HASH_SIZE], int num_leaves, uint8_t root[HASH_SIZE]);

// Compute the authentication path for a given leaf in a Merkle Tree.
void merkle_auth_path(const uint8_t leaves[][HASH_SIZE], int num_leaves, int leaf_index,
                      uint8_t auth_path[][HASH_SIZE], uint8_t root_out[HASH_SIZE]);
// Compute the root hash from a leaf and its authentication path.
void merkle_root_from_path(const uint8_t leaf[HASH_SIZE], int leaf_index,
                           const uint8_t auth_path[][HASH_SIZE], int height,
                           uint8_t root_out[HASH_SIZE]);

#endif
