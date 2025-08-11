#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>
#include "hash.h"
#include "xmss_config.h"

// WOTS Key structure
typedef struct {
    uint8_t **sk;
    uint8_t **pk;
} WOTSKey;

// WOTS signature structure
typedef struct {
    uint8_t **sig;
} WOTSSignature;

// WOTS Key and signiture memory management
int wots_alloc_key(WOTSKey *key, const xmss_params *params);
void wots_free_key(WOTSKey *key, const xmss_params *params);
int wots_alloc_sig(WOTSSignature *sig, const xmss_params *params);
void wots_free_sig(WOTSSignature *sig, const xmss_params *params);

// WOTS operations
void wots_compute_pk(const xmss_params *params, WOTSKey *key);
void wots_sign(const xmss_params *params, const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig);
void wots_verify(const xmss_params *params, const uint8_t *msg, const WOTSSignature *sig, WOTSKey *pk);

// Vulnerable function, for testing purposes only.
void wots_sign_vulnerable(const xmss_params *params, const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig);

#endif
