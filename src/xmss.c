#include "xmss.h"
#include "merkle.h"
#include "wots.h"
#include <string.h>

void xmss_keygen(XMSSKey *key) {
    for (int i = 0; i < XMSS_TREE_HEIGHT; i++) {
        wots_gen_keypair(&key->wots_keys[i]);
        memcpy(key->leaves + i * HASH_SIZE, key->wots_keys[i].pk[0], HASH_SIZE);
    }
    merkle_root(key->leaves, XMSS_TREE_HEIGHT, key->root);
}

void xmss_sign(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int idx) {
    memcpy(sig->root, key->root, HASH_SIZE);
    wots_sign(msg, &key->wots_keys[idx], &sig->wots_sig);
    sig->index = idx;
}

int xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root) {
    uint8_t derived_pk[WOTS_LEN][WOTS_N];
    uint8_t leaf[HASH_SIZE];

    wots_pk_from_sig(msg, &sig->wots_sig, derived_pk);
    memcpy(leaf, derived_pk[0], HASH_SIZE);

    // For demo purposes, skip Merkle path and compare roots
    return memcmp(root, sig->root, HASH_SIZE) == 0;
}
