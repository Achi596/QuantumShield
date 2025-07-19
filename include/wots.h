#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>
#include <stddef.h>

#define WOTS_W 16      /* Winternitz base */
#define WOTS_N 32      /* bytes per element (MATCH HASH_SIZE) */
#define WOTS_LEN 67    /* derived for N=32, w=16 */

typedef struct {
    uint8_t sk[WOTS_LEN][WOTS_N];
    uint8_t pk[WOTS_LEN][WOTS_N];
} WOTSKey;

typedef struct {
    uint8_t sig[WOTS_LEN][WOTS_N];
} WOTSSignature;

/* Key generation (random, legacy/testing) */
void wots_gen_keypair(WOTSKey *key);

/* Recompute pk from sk (used for deterministic derivation) */
void wots_compute_pk(WOTSKey *key);

/* Sign & rebuild pk from sig */
void wots_sign(const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig);
void wots_pk_from_sig(const uint8_t *msg, size_t msg_len, WOTSSignature *sig,
                      uint8_t pk[WOTS_LEN][WOTS_N]);

#endif
