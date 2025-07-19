#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>
#include "wots.h"
#include "hash.h"

#define XMSS_TREE_HEIGHT 2
#define XMSS_MAX_KEYS (1 << XMSS_TREE_HEIGHT)
#define XMSS_STATE_FILE "xmss_state.dat"
#define XMSS_KEY_FILE   "xmss_key.bin"

typedef struct {
    WOTSKey wots_keys[XMSS_MAX_KEYS];
    uint8_t root[HASH_SIZE];
} XMSSKey;

typedef struct {
    int index;
    WOTSSignature wots_sig;
    uint8_t auth_path[XMSS_TREE_HEIGHT][HASH_SIZE];
} XMSSSignature;

void xmss_keygen(XMSSKey *key);
void xmss_sign_auto(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig);
void xmss_sign_index(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int idx);
int  xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root);

int xmss_load_state(int *index);
int xmss_save_state(int index);

int xmss_save_key(const XMSSKey *key);
int xmss_load_key(XMSSKey *key);

#endif
