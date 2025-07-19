#include <string.h>
#include "merkle.h"
#include "hash.h"

void merkle_compute_root(const uint8_t leaves[][HASH_SIZE], int num_leaves, uint8_t root[HASH_SIZE]) {
    if (num_leaves == 1) {
        memcpy(root, leaves[0], HASH_SIZE);
        return;
    }

    int level_nodes = num_leaves;
    uint8_t level[level_nodes][HASH_SIZE];
    memcpy(level, leaves, num_leaves * HASH_SIZE);

    // Iteratively hash pairs of nodes until one root remains
    while (level_nodes > 1) {
        int parent_nodes = level_nodes / 2;
        for (int i = 0; i < parent_nodes; i++) {
            uint8_t concat[2 * HASH_SIZE];
            memcpy(concat, level[2*i], HASH_SIZE);
            memcpy(concat + HASH_SIZE, level[2*i + 1], HASH_SIZE);
            hash_sha256(concat, 2 * HASH_SIZE, level[i]);
        }
        level_nodes = parent_nodes;
    }
    memcpy(root, level[0], HASH_SIZE);
}
