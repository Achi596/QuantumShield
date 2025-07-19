#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>
#include "wots.h"
#include "hash.h"

#define XMSS_TREE_HEIGHT 2   // Adjust as needed (must be small for now while testing)

typedef struct {
    WOTSKey wots_keys[1 << XMSS_TREE_HEIGHT];  // One WOTS key per leaf
    uint8_t root[HASH_SIZE];                   // Merkle root (public key)
} XMSSKey;

typedef struct {
    int index;                                 // Leaf index used
    WOTSSignature wots_sig;                    // WOTS+ signature
    uint8_t auth_path[XMSS_TREE_HEIGHT][HASH_SIZE]; // Merkle authentication path
} XMSSSignature;

/* Key generation (fills all WOTS keys, computes root) */
void xmss_keygen(XMSSKey *key);

/* Sign (builds WOTS signature + authentication path) */
void xmss_sign(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int index);

/* Verify (rebuilds root from leaf + auth path) */
int  xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root);

#endif
