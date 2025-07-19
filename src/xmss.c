#include <string.h>
#include <stdio.h>
#include "xmss.h"
#include "wots.h"
#include "hash.h"
#include "merkle.h"

/* --- Build Merkle root from WOTS+ public keys --- */
static void compute_merkle_root(XMSSKey *key) {
    uint8_t leaves[1 << XMSS_TREE_HEIGHT][HASH_SIZE];

    // Hash each WOTS public key into a leaf
    for (int i = 0; i < (1 << XMSS_TREE_HEIGHT); i++) {
        uint8_t concat[WOTS_LEN * WOTS_N];
        for (int j = 0; j < WOTS_LEN; j++) {
            memcpy(concat + j * WOTS_N, key->wots_keys[i].pk[j], WOTS_N);
        }
        hash_sha256(concat, sizeof(concat), leaves[i]);
    }

    // Compute Merkle root
    merkle_compute_root(leaves, 1 << XMSS_TREE_HEIGHT, key->root);
}

/* --- Generate XMSS keypair --- */
void xmss_keygen(XMSSKey *key) {
    for (int i = 0; i < (1 << XMSS_TREE_HEIGHT); i++) {
        wots_gen_keypair(&key->wots_keys[i]);
    }
    compute_merkle_root(key);
}

/* --- Sign a message using WOTS+ leaf --- */
void xmss_sign(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int index) {
    sig->index = index;
    size_t msg_len = strlen((const char*)msg);  // For now, assume null-terminated string
    wots_sign(msg, msg_len, &key->wots_keys[index], &sig->wots_sig);
}

/* --- Verify a signature --- */
int xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root) {
    size_t msg_len = strlen((const char*)msg);
    uint8_t pk_recovered[WOTS_LEN][WOTS_N];

    // Recover WOTS public key from signature
    wots_pk_from_sig(msg, msg_len, &sig->wots_sig, pk_recovered);

    // Hash the recovered WOTS public key into a leaf
    uint8_t leaf_hash[HASH_SIZE];
    uint8_t concat[WOTS_LEN * WOTS_N];
    for (int j = 0; j < WOTS_LEN; j++) {
        memcpy(concat + j * WOTS_N, pk_recovered[j], WOTS_N);
    }
    hash_sha256(concat, sizeof(concat), leaf_hash);

    // *** NOTE ***
    // This directly compares leaf_hash with root (not real XMSS!)
    return (memcmp(leaf_hash, root, HASH_SIZE) == 0);
}
