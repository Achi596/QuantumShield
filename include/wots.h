#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>

#define WOTS_W 16 // Base for WOTS (WOTS+ uses base-16)
#define WOTS_LOG_W 4  // log2(16)
#define WOTS_N 32     // Hash output size in bytes

// Length calculations
#define WOTS_LEN1 (8 * WOTS_N / WOTS_LOG_W)              // # of message blocks
#define WOTS_LEN2 ((WOTS_LOG_W + 1) / WOTS_LOG_W)        // # of checksum blocks
#define WOTS_LEN (WOTS_LEN1 + WOTS_LEN2)                 // Total number of blocks

// Key and signature structures
typedef struct {
    uint8_t sk[WOTS_LEN][WOTS_N];  // Secret key
    uint8_t pk[WOTS_LEN][WOTS_N];  // Public key
} WOTSKey;

// Signature structure
typedef struct {
    uint8_t sig[WOTS_LEN][WOTS_N];
} WOTSSignature;

// Function declarations
void wots_compute_pk(WOTSKey *key);
void wots_sign(const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig);
void wots_verify(const uint8_t *msg, const WOTSSignature *sig, WOTSKey *pk);

#endif