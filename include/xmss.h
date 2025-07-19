#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>
#include "wots.h"
#include "hash.h"

#define XMSS_TREE_HEIGHT 2   // Minimal for now (2 leaves)

typedef struct {
    WOTSKey wots_keys[1 << XMSS_TREE_HEIGHT];  // WOTS keys for each leaf
    uint8_t root[HASH_SIZE];                   // Merkle root (public key)
} XMSSKey;

typedef struct {
    int index;                                 // Which leaf was used
    WOTSSignature wots_sig;                    // WOTS signature
} XMSSSignature;

/* XMSS operations */
void xmss_keygen(XMSSKey *key);
void xmss_sign(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int index);
int  xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root);

#endif
