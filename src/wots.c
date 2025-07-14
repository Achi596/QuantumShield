#include "wots.h"
#include "hash.h"
#include <stdlib.h>
#include <string.h>

void wots_gen_keypair(WOTSKey *key) {
    for (int i = 0; i < WOTS_LEN; i++) {
        for (int j = 0; j < WOTS_N; j++)
            key->sk[i][j] = rand() % 256;
        hash_sha256(key->sk[i], WOTS_N, key->pk[i]);
    }
}

void wots_sign(const uint8_t *msg, WOTSKey *key, WOTSSignature *sig) {
    for (int i = 0; i < WOTS_LEN; i++) {
        memcpy(sig->sig[i], key->sk[i], WOTS_N);
    }
}

void wots_pk_from_sig(const uint8_t *msg, WOTSSignature *sig, uint8_t pk[WOTS_LEN][WOTS_N]) {
    for (int i = 0; i < WOTS_LEN; i++) {
        hash_sha256(sig->sig[i], WOTS_N, pk[i]);
    }
}
