#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "wots.h"
#include "hash.h"
#include "util.h"

/* --- Memory Management --- */
static uint8_t** alloc_chains(int wots_len) {
    uint8_t **chains = malloc(wots_len * sizeof(uint8_t*));
    if (!chains) return NULL;
    for (int i = 0; i < wots_len; i++) {
        chains[i] = malloc(HASH_SIZE);
        if (!chains[i]) {
            // Rollback on failure
            for (int j = 0; j < i; j++) free(chains[j]);
            free(chains);
            return NULL;
        }
    }
    return chains;
}

static void free_chains(uint8_t **chains, int wots_len) {
    if (!chains) return;
    for (int i = 0; i < wots_len; i++) {
        free(chains[i]);
    }
    free(chains);
}

int wots_alloc_key(WOTSKey *key, const xmss_params *params) {
    key->sk = alloc_chains(params->wots_len);
    key->pk = alloc_chains(params->wots_len);
    if (!key->sk || !key->pk) {
        free_chains(key->sk, params->wots_len);
        free_chains(key->pk, params->wots_len);
        return -1;
    }
    return 0;
}

void wots_free_key(WOTSKey *key, const xmss_params *params) {
    if (key) {
        free_chains(key->sk, params->wots_len);
        free_chains(key->pk, params->wots_len);
    }
}

int wots_alloc_sig(WOTSSignature *sig, const xmss_params *params) {
    sig->sig = alloc_chains(params->wots_len);
    return sig->sig ? 0 : -1;
}

void wots_free_sig(WOTSSignature *sig, const xmss_params *params) {
    if (sig) {
        free_chains(sig->sig, params->wots_len);
    }
}


/* --- Internal: Constant-Time hash chain --- */
static void wots_chain_ct(uint8_t out[HASH_SIZE], const uint8_t in[HASH_SIZE], int start, int steps, int w) {
    uint8_t current_hash[HASH_SIZE];
    uint8_t next_hash[HASH_SIZE];
    memcpy(current_hash, in, HASH_SIZE);

    for (int i = 0; i < w - 1; i++) {
        // Always compute the next hash to keep timing consistent
        hash_shake256(current_hash, HASH_SIZE, next_hash, HASH_SIZE);
        
        // Conditionally select the next hash if we are within the desired step range
        uint32_t cond = (i >= start && i < start + steps);
        uint32_t mask = cond ? -1 : 0; // Create a mask of all 1s or all 0s
        conditional_select(current_hash, next_hash, current_hash, mask, HASH_SIZE);
    }
    memcpy(out, current_hash, HASH_SIZE);
    
    // Clean up stack variables
    secure_zero_memory(current_hash, HASH_SIZE);
    secure_zero_memory(next_hash, HASH_SIZE);
}


/* Convert msg hash -> base-w digits and compute checksum */
static void base_w_and_checksum(const uint8_t *input, const xmss_params *params, uint8_t *output) {
    int in = 0;
    int out = 0;
    uint32_t total = 0;
    int bits = 0;
    uint16_t checksum = 0;
    
    // Message part
    for (int i = 0; i < params->wots_len1; i++) {
        if (bits < params->log_w) {
            total = (total << 8) | input[in++];
            bits += 8;
        }
        bits -= params->log_w;
        output[out++] = (total >> bits) & (params->w - 1);
        checksum += params->w - 1 - output[i];
    }

    // Checksum part
    checksum <<= (8 - ((params->wots_len2 * params->log_w) % 8)) % 8;
    for (int i = 0; i < params->wots_len2; i++) {
        output[out++] = (checksum >> ((params->wots_len2 - 1 - i) * params->log_w)) & (params->w - 1);
    }
}

/* Compute pk from existing sk */
void wots_compute_pk(const xmss_params *params, WOTSKey *key) {
    for (int i = 0; i < params->wots_len; i++) {
        wots_chain_ct(key->pk[i], key->sk[i], 0, params->w - 1, params->w);
    }
}

// Sign a message using WOTS
void wots_sign(const xmss_params *params, const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig) {
    uint8_t msg_hash[HASH_SIZE];
    hash_shake256(msg, msg_len, msg_hash, HASH_SIZE);

    uint8_t base_w_digits[params->wots_len];
    base_w_and_checksum(msg_hash, params, base_w_digits);

    for (int i = 0; i < params->wots_len; i++) {
        wots_chain_ct(sig->sig[i], key->sk[i], 0, base_w_digits[i], params->w);
    }
    
    secure_zero_memory(msg_hash, HASH_SIZE);
    secure_zero_memory(base_w_digits, sizeof(base_w_digits));
}


// Verify a WOTS signature
void wots_verify(const xmss_params *params, const uint8_t *msg, const WOTSSignature *sig, WOTSKey *pk_from_sig) {
    uint8_t msg_hash[HASH_SIZE];
    hash_shake256(msg, HASH_SIZE, msg_hash, HASH_SIZE);
    
    uint8_t base_w_digits[params->wots_len];
    base_w_and_checksum(msg_hash, params, base_w_digits);
    
    for (int i = 0; i < params->wots_len; i++) {
        int steps = params->w - 1 - base_w_digits[i];
        wots_chain_ct(pk_from_sig->pk[i], sig->sig[i], base_w_digits[i], steps, params->w);
    }

    secure_zero_memory(msg_hash, HASH_SIZE);
    secure_zero_memory(base_w_digits, sizeof(base_w_digits));
}

/*
 ============================================================================
    WARNING: The following functions are for demonstration purposes ONLY.
    They are intentionally VULNERABLE to timing attacks.
    DO NOT use them in production.
 ============================================================================
*/

// VULNERABLE hash chain function. The number of loops depends on 'steps'.
static void wots_chain_vulnerable(uint8_t out[HASH_SIZE], const uint8_t in[HASH_SIZE], int start, int steps) {
    uint8_t tmp[HASH_SIZE];
    memcpy(tmp, in, HASH_SIZE);
    // The loop bound is data-dependent, which is the source of the timing leak.
    for (int i = start; i < start + steps; i++) {
        hash_shake256(tmp, HASH_SIZE, tmp, HASH_SIZE);
    }
    memcpy(out, tmp, HASH_SIZE);
}

// VULNERABLE WOTS sign function using the leaky hash chain.
void wots_sign_vulnerable(const xmss_params *params, const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig) {
    uint8_t msg_hash[HASH_SIZE];
    hash_shake256(msg, msg_len, msg_hash, HASH_SIZE);

    uint8_t base_w_digits[params->wots_len];
    // This is a simplified base-w conversion for the PoC.
    // In a real attack, the attacker would use the proper checksummed base-w digits.
    for (int i = 0; i < params->wots_len; i++) {
        base_w_digits[i] = msg_hash[i % HASH_SIZE] % params->w;
    }

    for (int i = 0; i < params->wots_len; i++) {
        wots_chain_vulnerable(sig->sig[i], key->sk[i], 0, base_w_digits[i]);
    }
    
    secure_zero_memory(msg_hash, HASH_SIZE);
    secure_zero_memory(base_w_digits, sizeof(base_w_digits));
}