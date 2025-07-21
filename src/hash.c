#include "hash.h"
#include <openssl/evp.h>
#include <stdio.h>

// Hash function using SHAKE256
// This function takes an input buffer and produces a variable-length output
void hash_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "hash_shake256: EVP_MD_CTX_new failed\n");
        return;
    }
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, in, inlen) != 1 ||
        EVP_DigestFinalXOF(ctx, out, outlen) != 1) {
        fprintf(stderr, "hash_shake256: SHAKE256 hashing failed\n");
    }
    EVP_MD_CTX_free(ctx);
}
