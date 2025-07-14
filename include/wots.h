#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>

#define WOTS_LEN 1     // Minimal prototype
#define WOTS_N 32       // Hash output length

typedef struct {
    uint8_t sk[WOTS_LEN][WOTS_N];
    uint8_t pk[WOTS_LEN][WOTS_N];
} WOTSKey;

typedef struct {
    uint8_t sig[WOTS_LEN][WOTS_N];
} WOTSSignature;

void wots_gen_keypair(WOTSKey *key);
void wots_sign(const uint8_t *msg, WOTSKey *key, WOTSSignature *sig);
void wots_pk_from_sig(const uint8_t *msg, WOTSSignature *sig, uint8_t pk[WOTS_LEN][WOTS_N]);

#endif
