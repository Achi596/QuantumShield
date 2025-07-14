#include "hash.h"
#include <openssl/sha.h>
#include <string.h>

void hash_sha256(const uint8_t *input, size_t len, uint8_t *out) {
    SHA256(input, len, out);
}
