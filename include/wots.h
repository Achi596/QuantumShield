#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>

#define WOTS_W 16      // Winternitz base
#define WOTS_N 32      // Hash output (e.g., 32 bytes)
#define WOTS_LEN 67    // Derived for w=16 and N=32

typedef struct {
    uint8_t sk[WOTS_LEN][WOTS_N];  // Secret seeds
    uint8_t pk[WOTS_LEN][WOTS_N];  // Public key
} WOTSKey;

typedef struct {
    uint8_t sig[WOTS_LEN][WOTS_N]; // WOTS signature
} WOTSSignature;

/* Key generation */
void wots_gen_keypair(WOTSKey *key);

/* Signing and verification */
void wots_sign(const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig);
void wots_pk_from_sig(const uint8_t *msg, size_t msg_len, WOTSSignature *sig, uint8_t pk[WOTS_LEN][WOTS_N]);

#endif
