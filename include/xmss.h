#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>
#include "wots.h"
#include "hash.h"
#include "xmss_config.h"

// Filenames
#define XMSS_STATE_FILE "xmss_state.dat"
#define XMSS_KEY_FILE   "xmss_key.bin"

#define XMSS_SEED_BYTES 32

// XMSS Key structure
typedef struct {
    uint8_t  seed[XMSS_SEED_BYTES];
    uint8_t  root[HASH_SIZE];
} XMSSKey;

// XMSS Signature structure
typedef struct {
    int index;
    WOTSSignature *wots_sig;
    uint8_t **auth_path; // [h][HASH_SIZE]
} XMSSSignature;

// Memory management
int xmss_alloc_sig(XMSSSignature *sig, const xmss_params *params);
void xmss_free_sig(XMSSSignature *sig, const xmss_params *params);

// Key lifecycle
void xmss_keygen(const xmss_params *params, XMSSKey *key);
int  xmss_save_key(const XMSSKey *key, const xmss_params *params);
int  xmss_load_key(XMSSKey *key, xmss_params *params);

// Signing
void xmss_sign_auto(const xmss_params *params, const uint8_t *msg, XMSSKey *key, XMSSSignature *sig);
void xmss_sign_index(const xmss_params *params, const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int idx);

// Verify
int  xmss_verify(const xmss_params *params, const uint8_t *msg, XMSSSignature *sig, const uint8_t *root);

// State persistence
int xmss_load_state(int *index);
int xmss_save_state(int index);

// Helper function to generate WOTS key
void xmss_generate_wots_key(const xmss_params *params, XMSSKey *key, int index, WOTSKey *wots_key);

#endif
