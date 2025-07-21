#include <stdio.h>
#include <string.h>
#include "xmss_eth.h"

/* Little-endian u32 helpers */
static void u32le_store(uint8_t b[4], uint32_t x) {
    b[0] = (uint8_t)x;
    b[1] = (uint8_t)(x >> 8);
    b[2] = (uint8_t)(x >> 16);
    b[3] = (uint8_t)(x >> 24);
}
static uint32_t u32le_load(const uint8_t b[4]) {
    return ((uint32_t)b[0])       |
           ((uint32_t)b[1] << 8)  |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

/* Serialize */
int xmss_eth_serialize(const XMSSSignature *sig,
                       uint8_t *out, size_t out_cap,
                       size_t *out_len)
{
    if (!sig || !out) return -1;
    size_t need = xmss_eth_sig_size();
    if (out_cap < need) return -1;

    /* index */
    u32le_store(out, (uint32_t)sig->index);
    size_t pos = 4;

    /* WOTS sig chains */
    for (int i = 0; i < WOTS_LEN; i++) {
        memcpy(out + pos, sig->wots_sig.sig[i], HASH_SIZE);
        pos += HASH_SIZE;
    }

    /* Auth path nodes */
    for (int i = 0; i < XMSS_TREE_HEIGHT; i++) {
        memcpy(out + pos, sig->auth_path[i], HASH_SIZE);
        pos += HASH_SIZE;
    }

    if (out_len) *out_len = pos;
    return 0;
}

/* Deserialize */
int xmss_eth_deserialize(XMSSSignature *sig,
                         const uint8_t *in, size_t in_len)
{
    if (!sig || !in) return -1;
    size_t need = xmss_eth_sig_size();
    if (in_len != need) return -1;

    size_t pos = 0;
    sig->index = (int)u32le_load(in + pos);
    pos += 4;

    /* WOTS sig */
    for (int i = 0; i < WOTS_LEN; i++) {
        memcpy(sig->wots_sig.sig[i], in + pos, HASH_SIZE);
        pos += HASH_SIZE;
    }

    /* Auth path */
    for (int i = 0; i < XMSS_TREE_HEIGHT; i++) {
        memcpy(sig->auth_path[i], in + pos, HASH_SIZE);
        pos += HASH_SIZE;
    }

    return 0;
}

/* Save to file */
int xmss_eth_save_sig(const char *path, const XMSSSignature *sig)
{
    uint8_t buf[XMSS_ETH_SIG_MAX_BYTES];
    size_t need = xmss_eth_sig_size();
    if (need > sizeof(buf)) {
        fprintf(stderr, "ERROR: XMSS Ethereum sig (%zu bytes) exceeds hard max %zu.\n",
                need, (size_t)sizeof(buf));
        return -1;
    }
    size_t written = 0;
    if (xmss_eth_serialize(sig, buf, sizeof(buf), &written) != 0) {
        return -1;
    }
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, written, 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* Load from file */
int xmss_eth_load_sig(const char *path, XMSSSignature *sig, size_t *sig_len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0; /* not found */
    uint8_t buf[XMSS_ETH_SIG_MAX_BYTES];

    size_t need = xmss_eth_sig_size();
    size_t got = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (got != need) {
        fprintf(stderr, "ERROR: Signature file size %zu != expected %zu.\n", got, need);
        return -1;
    }
    if (xmss_eth_deserialize(sig, buf, got) != 0) {
        return -1;
    }
    if (sig_len_out) *sig_len_out = got;
    return 1;
}
