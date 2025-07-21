#include <stdio.h>
#include <string.h>
#include "xmss_io.h"

/* ---------------- Little-endian helpers ----------------*/
static void u32le_store(uint8_t b[4], uint32_t x) {
    b[0] = (uint8_t)x;
    b[1] = (uint8_t)(x >> 8);
    b[2] = (uint8_t)(x >> 16);
    b[3] = (uint8_t)(x >> 24);
}

static uint32_t u32le_load(const uint8_t b[4]) {
    return ((uint32_t)b[0]) |
           ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static void u16le_store(uint8_t b[2], uint16_t x) {
    b[0] = (uint8_t)x;
    b[1] = (uint8_t)(x >> 8);
}

static uint16_t u16le_load(const uint8_t b[2]) {
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

/* ---------------- Key I/O ---------------- */

int xmss_io_save_key(const char *path, const XMSSKey *key,
                     uint8_t hash_id)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* header layout: magic(4) ver(2) hash(1) h(1) w(1) pad(3) */
    uint8_t hdr[4+2+1+1+1+3];
    u32le_store(hdr+0, XMSS_IO_MAGIC_KEY);
    u16le_store(hdr+4, XMSS_IO_VERSION);
    hdr[6] = hash_id;
    hdr[7] = (uint8_t)XMSS_TREE_HEIGHT;
    hdr[8] = (uint8_t)WOTS_W;
    memset(hdr+9, 0, 3);

    if (fwrite(hdr, sizeof hdr, 1, f) != 1) { fclose(f); return -1; }
    if (fwrite(key, sizeof *key, 1, f) != 1) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int xmss_io_load_key(const char *path, XMSSKey *key,
                     uint8_t *hash_id_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0; /* not found */

    uint8_t hdr[4+2+1+1+1+3];
    if (fread(hdr, sizeof hdr, 1, f) != 1) { fclose(f); return -1; }

    uint32_t magic = u32le_load(hdr+0);
    uint16_t ver   = u16le_load(hdr+4);
    uint8_t  h_id  = hdr[6];
    uint8_t  h     = hdr[7];
    uint8_t  w     = hdr[8];

    if (magic != XMSS_IO_MAGIC_KEY || ver != XMSS_IO_VERSION) {
        fclose(f);
        return -1;
    }
    /* Basic param sanity */
    if (h != XMSS_TREE_HEIGHT || w != WOTS_W) {
        fclose(f);
        return -1;
    }

    if (fread(key, sizeof *key, 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);

    if (hash_id_out) *hash_id_out = h_id;
    return 1;
}

/* ---------------- Signature I/O ---------------- */

int xmss_io_save_sig(const char *path, const XMSSSignature *sig,
                     uint8_t hash_id)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* header: magic(4) ver(2) hash(1) h(1) pad(2) */
    uint8_t hdr[4+2+1+1+2];
    u32le_store(hdr+0, XMSS_IO_MAGIC_SIG);
    u16le_store(hdr+4, XMSS_IO_VERSION);
    hdr[6] = hash_id;
    hdr[7] = (uint8_t)XMSS_TREE_HEIGHT;
    memset(hdr+8, 0, 2);

    if (fwrite(hdr, sizeof hdr, 1, f) != 1) { fclose(f); return -1; }
    if (fwrite(sig, sizeof *sig, 1, f) != 1) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int xmss_io_load_sig(const char *path, XMSSSignature *sig,
                     uint8_t *hash_id_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0; /* not found */

    uint8_t hdr[4+2+1+1+2];
    if (fread(hdr, sizeof hdr, 1, f) != 1) { fclose(f); return -1; }

    uint32_t magic = u32le_load(hdr+0);
    uint16_t ver   = u16le_load(hdr+4);
    uint8_t  h_id  = hdr[6];
    uint8_t  h     = hdr[7];

    if (magic != XMSS_IO_MAGIC_SIG || ver != XMSS_IO_VERSION) {
        fclose(f);
        return -1;
    }
    if (h != XMSS_TREE_HEIGHT) {
        fclose(f);
        return -1;
    }

    if (fread(sig, sizeof *sig, 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);

    if (hash_id_out) *hash_id_out = h_id;
    return 1;
}
