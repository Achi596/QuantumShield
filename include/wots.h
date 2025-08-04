#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>
#include "hash.h"
#include "xmss_config.h"

// Key and signature structures now use pointers for dynamic allocation
typedef struct {
    uint8_t **sk; // Secret key: [wots_len][HASH_SIZE]
    uint8_t **pk; // Public key: [wots_len][HASH_SIZE]
} WOTSKey;

typedef struct {
    uint8_t **sig; // Signature: [wots_le  n][HASH_SIZE]
} WOTSSignature;

// Memory management for dynamic WOTS structures
int wots_alloc_key(WOTSKey *key, const xmss_params *params);
void wots_free_key(WOTSKey *key, const xmss_params *params);
int wots_alloc_sig(WOTSSignature *sig, const xmss_params *params);
void wots_free_sig(WOTSSignature *sig, const xmss_params *params);

// Function declarations updated to accept xmss_params
void wots_compute_pk(const xmss_params *params, WOTSKey *key);
void wots_sign(const xmss_params *params, const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig);
void wots_verify(const xmss_params *params, const uint8_t *msg, const WOTSSignature *sig, WOTSKey *pk);

// Declaration for the vulnerable function, for testing purposes only.
void wots_sign_vulnerable(const xmss_params *params, const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig);

#endif