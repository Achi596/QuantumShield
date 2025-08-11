// import standard libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// import project-specific headers
#include "xmss_eth.h"
#include "hash.h"

/* Little-endian u32 helpers */
static void u32le_store(uint8_t b[4], uint32_t x) {
    b[0] = (uint8_t)x; b[1] = (uint8_t)(x >> 8); b[2] = (uint8_t)(x >> 16); b[3] = (uint8_t)(x >> 24);
}

// Load a 32-bit unsigned integer from little-endian byte array
static uint32_t u32le_load(const uint8_t b[4]) {
    return ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

// Convert XMSS signature to Ethereum compact format
int xmss_eth_serialize(const xmss_params *params, const XMSSSignature *sig,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!sig || !out) return -1;
    size_t need = xmss_eth_sig_size(params);
    if (out_cap < need) return -1;

    u32le_store(out, (uint32_t)sig->index);
    size_t pos = 4;

    for (int i = 0; i < params->wots_len; i++) {
        memcpy(out + pos, sig->wots_sig->sig[i], HASH_SIZE);
        pos += HASH_SIZE;
    }

    for (int i = 0; i < params->h; i++) {
        memcpy(out + pos, sig->auth_path[i], HASH_SIZE);
        pos += HASH_SIZE;
    }

    if (out_len) *out_len = pos;
    return 0;
}

// Deserialize XMSS signature from Ethereum compact format
int xmss_eth_deserialize(xmss_params *params, XMSSSignature *sig,
                         const uint8_t *in, size_t in_len)
{
    if (!sig || !in) return -1;
    size_t need = xmss_eth_sig_size(params);
    if (in_len != need) {
        fprintf(stderr, "ERROR: xmss_eth_deserialize: input length %zu does not match expected size %zu\n", in_len, need);
        return -1;
    }

    size_t pos = 0;
    sig->index = (int)u32le_load(in + pos);
    pos += 4;

    for (int i = 0; i < params->wots_len; i++) {
        memcpy(sig->wots_sig->sig[i], in + pos, HASH_SIZE);
        pos += HASH_SIZE;
    }

    for (int i = 0; i < params->h; i++) {
        memcpy(sig->auth_path[i], in + pos, HASH_SIZE);
        pos += HASH_SIZE;
    }
    return 0;
}

// Save the Ethereum compact format to a file
int xmss_eth_save_sig(const char *path, const XMSSSignature *sig, const xmss_params *params) {
    size_t need = xmss_eth_sig_size(params);
    uint8_t *buf = malloc(need);
    if (!buf) return -1;
    
    size_t written = 0;
    if (xmss_eth_serialize(params, sig, buf, need, &written) != 0) {
        free(buf);
        return -1;
    }
    
    FILE *f = fopen(path, "wb");
    if (!f) { free(buf); return -1; }

    printf("Loaded key (h=%d, w=%d)\n", params->h, params->w);
    
    // Write params first, then the signature data
    int ok = 1;
    if (fwrite(&params->h, sizeof(int), 1, f) != 1) ok = 0;
    if (ok && fwrite(&params->w, sizeof(int), 1, f) != 1) ok = 0;
    if (ok && fwrite(buf, written, 1, f) != 1) ok = 0;
    
    fclose(f);
    free(buf);
    return ok ? 0 : -1;
}

// Load the Ethereum compact format from a file
int xmss_eth_load_sig(const char *path, XMSSSignature *sig, xmss_params *params) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0; /* not found */

    int h, w;
    if (fread(&h, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&w, sizeof(int), 1, f) != 1) { fclose(f); return -1; }

    printf("Loaded key (h=%d, w=%d)\n", h, w);

    if (xmss_params_init(params, h, w) != 0) {
        fprintf(stderr, "Failed to init params from signature file\n");
        fclose(f);
        return -1;
    }

    size_t need = xmss_eth_sig_size(params);
    uint8_t *buf = malloc(need);
    if (!buf) { fclose(f); return -1; }

    size_t got = fread(buf, 1, need + 1, f); // Read one extra byte to check for trailing data
    fclose(f);

    if (got != need) {
        fprintf(stderr, "ERROR: Signature file size mismatch. Got %zu, expected %zu.\n", got, need);
        free(buf);
        return -1;
    }
    
    if (xmss_alloc_sig(sig, params) != 0) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        free(buf);
        return -1;
    }

    int result = xmss_eth_deserialize(params, sig, buf, got);
    free(buf);
    
    return (result == 0) ? 1 : -1;
}