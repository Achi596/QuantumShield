#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "wots.h"
#include "hash.h"
#include "csprng.h"

/* --- Internal: hash chain --- */
static void wots_chain(uint8_t out[WOTS_N], const uint8_t in[WOTS_N], int start, int steps) {
    uint8_t tmp[WOTS_N];
    memcpy(tmp, in, WOTS_N);
    for (int i = start; i < start + steps && i < WOTS_W; i++) {
        /* Rehash in place */
        hash_shake256(tmp, WOTS_N, tmp, WOTS_N);
    }
    memcpy(out, tmp, WOTS_N);
}

/* Convert 32-byte msg hash -> base-w digits */
static void base_w(const uint8_t *input, int input_len, int w, int out_len, uint8_t *output) {
    /* w=16 -> consume 4 bits per digit */
    int bits_per_digit = 4; /* log2(16) */
    int total = 0, bits = 0, out = 0;
    for (int in = 0; in < input_len; in++) {
        total = (total << 8) | input[in];
        bits += 8;
        while (bits >= bits_per_digit && out < out_len) {
            bits -= bits_per_digit;
            output[out++] = (total >> bits) & ((1 << bits_per_digit) - 1);
        }
    }
    while (out < out_len) output[out++] = 0;
}

/* Compute pk from existing sk */
void wots_compute_pk(WOTSKey *key) {
    for (int i = 0; i < WOTS_LEN; i++) {
        wots_chain(key->pk[i], key->sk[i], 0, WOTS_W - 1);
    }
}

// Sign a message using WOTS
// This computes the signature based on the message hash and the secret key
void wots_sign(const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig) {
    uint8_t msg_hash[WOTS_N];
    hash_shake256(msg, msg_len, msg_hash, WOTS_N);

    uint8_t a[WOTS_LEN] = {0};
    base_w(msg_hash, WOTS_N, WOTS_W, WOTS_LEN, a);

    for (int i = 0; i < WOTS_LEN; i++) {
        wots_chain(sig->sig[i], key->sk[i], 0, a[i]);
    }
}

// Rebuild the public key from the signature
// This uses the message hash and the signature to compute the public key
void wots_pk_from_sig(const uint8_t *msg, size_t msg_len, WOTSSignature *sig,
                      uint8_t pk[WOTS_LEN][WOTS_N]) {
    uint8_t msg_hash[WOTS_N];
    hash_shake256(msg, msg_len, msg_hash, WOTS_N);

    uint8_t a[WOTS_LEN] = {0};
    base_w(msg_hash, WOTS_N, WOTS_W, WOTS_LEN, a);

    for (int i = 0; i < WOTS_LEN; i++) {
        wots_chain(pk[i], sig->sig[i], a[i], WOTS_W - 1 - a[i]);
    }
}
