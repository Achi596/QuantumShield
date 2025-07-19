#include <stdlib.h>
#include <string.h>
#include "wots.h"
#include "hash.h"
#include "csprng.h"

static void wots_chain(uint8_t out[WOTS_N], const uint8_t in[WOTS_N], int start, int steps) {
    uint8_t tmp[WOTS_N];
    memcpy(tmp, in, WOTS_N);
    for (int i = start; i < start + steps && i < WOTS_W; i++) {
        hash_shake256(tmp, WOTS_N, tmp, HASH_SIZE);
    }
    memcpy(out, tmp, WOTS_N);
}

static void base_w(const uint8_t *input, int input_len, int w, int out_len, uint8_t *output) {
    // Convert input to base-w representation
    int in = 0, out = 0;
    int total = 0, bits = 0;
    for (in = 0; in < input_len; in++) {
        total = (total << 8) | input[in];
        bits += 8;
        while (bits >= 4 && out < out_len) { // log2(16)=4
            bits -= 4;
            output[out++] = (total >> bits) & 0xF;
        }
    }
}

void wots_gen_keypair(WOTSKey *key) {
    for (int i = 0; i < WOTS_LEN; i++) {
        csprng_random_bytes(key->sk[i], WOTS_N);
        wots_chain(key->pk[i], key->sk[i], 0, WOTS_W - 1);
    }
}

void wots_sign(const uint8_t *msg, size_t msg_len, WOTSKey *key, WOTSSignature *sig) {
    uint8_t msg_hash[WOTS_N];
    hash_shake256(msg, msg_len, msg_hash, HASH_SIZE);

    uint8_t a[WOTS_LEN] = {0};
    base_w(msg_hash, WOTS_N, WOTS_W, WOTS_LEN, a);

    for (int i = 0; i < WOTS_LEN; i++) {
        wots_chain(sig->sig[i], key->sk[i], 0, a[i]);
    }
}

void wots_pk_from_sig(const uint8_t *msg, size_t msg_len, WOTSSignature *sig, uint8_t pk[WOTS_LEN][WOTS_N]) {
    uint8_t msg_hash[WOTS_N];
    hash_shake256(msg, msg_len, msg_hash, HASH_SIZE);

    uint8_t a[WOTS_LEN] = {0};
    base_w(msg_hash, WOTS_N, WOTS_W, WOTS_LEN, a);

    for (int i = 0; i < WOTS_LEN; i++) {
        wots_chain(pk[i], sig->sig[i], a[i], WOTS_W - 1 - a[i]);
    }
}

