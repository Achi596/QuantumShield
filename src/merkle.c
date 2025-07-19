#include <string.h>
#include "merkle.h"
#include "hash.h"

/* Compute Merkle root from an array of leaves */
void merkle_compute_root(const uint8_t leaves[][HASH_SIZE], int num_leaves, uint8_t root[HASH_SIZE]) {
    if (num_leaves == 1) {
        memcpy(root, leaves[0], HASH_SIZE);
        return;
    }

    int level_nodes = num_leaves;
    /* Copy leaves into a working buffer */
    /* For small trees a VLA is fine; for bigger trees allocate dynamically */
    uint8_t level[level_nodes][HASH_SIZE];
    memcpy(level, leaves, num_leaves * HASH_SIZE);

    while (level_nodes > 1) {
        int parent_nodes = level_nodes / 2;
        for (int i = 0; i < parent_nodes; i++) {
            uint8_t concat[2 * HASH_SIZE];
            memcpy(concat, level[2*i], HASH_SIZE);
            memcpy(concat + HASH_SIZE, level[2*i + 1], HASH_SIZE);
            hash_sha256(concat, sizeof(concat), level[i]);
        }
        level_nodes = parent_nodes;
    }
    memcpy(root, level[0], HASH_SIZE);
}

/* Build auth path for a given leaf index and also recompute root */
void merkle_auth_path(const uint8_t leaves[][HASH_SIZE], int num_leaves, int leaf_index,
                      uint8_t auth_path[][HASH_SIZE], uint8_t root_out[HASH_SIZE]) {
    int level_nodes = num_leaves;
    int idx = leaf_index;

    uint8_t level[level_nodes][HASH_SIZE];
    memcpy(level, leaves, num_leaves * HASH_SIZE);

    int height = 0;
    while (level_nodes > 1) {
        int sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        memcpy(auth_path[height], level[sibling], HASH_SIZE);

        int parent_nodes = level_nodes / 2;
        for (int i = 0; i < parent_nodes; i++) {
            uint8_t concat[2 * HASH_SIZE];
            memcpy(concat, level[2*i], HASH_SIZE);
            memcpy(concat + HASH_SIZE, level[2*i + 1], HASH_SIZE);
            hash_sha256(concat, sizeof(concat), level[i]);
        }
        idx /= 2;
        level_nodes = parent_nodes;
        height++;
    }
    memcpy(root_out, level[0], HASH_SIZE);
}

/* Reconstruct root from leaf + auth path */
void merkle_root_from_path(const uint8_t leaf[HASH_SIZE], int leaf_index,
                           const uint8_t auth_path[][HASH_SIZE], int height,
                           uint8_t root_out[HASH_SIZE]) {
    uint8_t current[HASH_SIZE];
    memcpy(current, leaf, HASH_SIZE);
    int idx = leaf_index;

    for (int h = 0; h < height; h++) {
        uint8_t concat[2 * HASH_SIZE];
        if (idx % 2 == 0) {
            memcpy(concat, current, HASH_SIZE);
            memcpy(concat + HASH_SIZE, auth_path[h], HASH_SIZE);
        } else {
            memcpy(concat, auth_path[h], HASH_SIZE);
            memcpy(concat + HASH_SIZE, current, HASH_SIZE);
        }
        hash_sha256(concat, sizeof(concat), current);
        idx /= 2;
    }
    memcpy(root_out, current, HASH_SIZE);
}
