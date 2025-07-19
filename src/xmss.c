#include <string.h>
#include <stdio.h>
#include "xmss.h"
#include "wots.h"
#include "hash.h"
#include "merkle.h"

/* Hash a full WOTS public key (concatenated chains) into a leaf */
static void wots_pk_to_leaf(const WOTSKey *wots, uint8_t leaf[HASH_SIZE]) {
    uint8_t concat[WOTS_LEN * WOTS_N];
    for (int j = 0; j < WOTS_LEN; j++) {
        memcpy(concat + j * WOTS_N, wots->pk[j], WOTS_N);
    }
    hash_sha256(concat, sizeof(concat), leaf);
}

void xmss_keygen(XMSSKey *key) {
    int total_leaves = 1 << XMSS_TREE_HEIGHT;
    for (int i = 0; i < total_leaves; i++) {
        wots_gen_keypair(&key->wots_keys[i]);
    }

    // Build leaves
    uint8_t leaves[1 << XMSS_TREE_HEIGHT][HASH_SIZE];
    for (int i = 0; i < total_leaves; i++) {
        wots_pk_to_leaf(&key->wots_keys[i], leaves[i]);
    }

    // Compute root
    merkle_compute_root(leaves, total_leaves, key->root);
}

void xmss_sign(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int index) {
    int total_leaves = 1 << XMSS_TREE_HEIGHT;
    if (index < 0 || index >= total_leaves) {
        fprintf(stderr, "xmss_sign: invalid index %d\n", index);
        return;
    }

    sig->index = index;

    // Produce WOTS+ signature for this leaf
    size_t msg_len = strlen((const char*)msg); // For prototype; later pass explicit length
    wots_sign(msg, msg_len, &key->wots_keys[index], &sig->wots_sig);

    // Recompute all leaf hashes (prototype; could cache later)
    uint8_t leaves[1 << XMSS_TREE_HEIGHT][HASH_SIZE];
    for (int i = 0; i < total_leaves; i++) {
        wots_pk_to_leaf(&key->wots_keys[i], leaves[i]);
    }

    // Build authentication path + (re)confirm root
    uint8_t recomputed_root[HASH_SIZE];
    merkle_auth_path(leaves, total_leaves, index, sig->auth_path, recomputed_root);

    // Optional: sanity check
    if (memcmp(recomputed_root, key->root, HASH_SIZE) != 0) {
        fprintf(stderr, "xmss_sign: WARNING root mismatch (internal error)\n");
    }
}

int xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root) {
    size_t msg_len = strlen((const char*)msg);
    int total_leaves = 1 << XMSS_TREE_HEIGHT;
    int index = sig->index;
    if (index < 0 || index >= total_leaves) {
        return 0;
    }

    // Recover WOTS+ public key from signature
    uint8_t pk_recovered[WOTS_LEN][WOTS_N];
    wots_pk_from_sig(msg, msg_len, &sig->wots_sig, pk_recovered);

    // Hash recovered public key into its leaf hash
    uint8_t leaf[HASH_SIZE];
    {
        uint8_t concat[WOTS_LEN * WOTS_N];
        for (int j = 0; j < WOTS_LEN; j++) {
            memcpy(concat + j * WOTS_N, pk_recovered[j], WOTS_N);
        }
        hash_sha256(concat, sizeof(concat), leaf);
    }

    // Reconstruct root from leaf + auth path
    uint8_t computed_root[HASH_SIZE];
    merkle_root_from_path(leaf, index, sig->auth_path, XMSS_TREE_HEIGHT, computed_root);

    // Compare to claimed root
    return memcmp(computed_root, root, HASH_SIZE) == 0;
}
