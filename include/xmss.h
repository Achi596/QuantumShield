#ifndef XMSS_H
#define XMSS_H

#include "wots.h"
#include "hash.h"

#define XMSS_TREE_HEIGHT 2  // For now: 2 WOTS keys / leaves

typedef struct {
    WOTSKey wots_keys[XMSS_TREE_HEIGHT];
    uint8_t leaves[XMSS_TREE_HEIGHT * HASH_SIZE];
    uint8_t root[HASH_SIZE];
} XMSSKey;

typedef struct {
    int index;
    WOTSSignature wots_sig;
    uint8_t root[HASH_SIZE];
} XMSSSignature;

void xmss_keygen(XMSSKey *key);
void xmss_sign(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int idx);
int xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root);

#endif
