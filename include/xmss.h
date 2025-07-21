#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>
#include "wots.h"
#include "hash.h"

#define XMSS_TREE_HEIGHT 2
#define XMSS_MAX_KEYS (1 << XMSS_TREE_HEIGHT)

/* Filenames */
#define XMSS_STATE_FILE "xmss_state.dat"
#define XMSS_KEY_FILE   "xmss_key.bin"

/* Master seed size for PRF-based key derivation */
#define XMSS_SEED_BYTES 32

// XMSS key structure
typedef struct {
    uint8_t  seed[XMSS_SEED_BYTES];            /* master seed */
    WOTSKey  wots_keys[XMSS_MAX_KEYS];         /* expanded (derived) WOTS keys */
    uint8_t  root[HASH_SIZE];                  /* Merkle root */
} XMSSKey;

// XMSS signature structure
typedef struct {
    int index;
    WOTSSignature wots_sig;
    uint8_t auth_path[XMSS_TREE_HEIGHT][HASH_SIZE];
} XMSSSignature;

/* Key lifecycle */
void xmss_keygen(XMSSKey *key);
void xmss_keygen_seeded(XMSSKey *key, const uint8_t seed[XMSS_SEED_BYTES]);

int  xmss_save_key(const XMSSKey *key);
int  xmss_load_key(XMSSKey *key);

/* Signing */
void xmss_sign_auto (const uint8_t *msg, XMSSKey *key, XMSSSignature *sig);
void xmss_sign_index(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int idx);

/* Verify */
int  xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root);

/* State persistence */
int xmss_load_state(int *index);
int xmss_save_state(int index);

#endif
