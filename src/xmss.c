#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "xmss.h"
#include "wots.h"
#include "hash.h"
#include "merkle.h"
#include "csprng.h"
#include "xmss_io.h"

/* Encode little-endian */
static void u32le(uint8_t out[4], uint32_t x) {
    out[0] = (uint8_t)(x);
    out[1] = (uint8_t)(x >> 8);
    out[2] = (uint8_t)(x >> 16);
    out[3] = (uint8_t)(x >> 24);
}
static void u16le(uint8_t out[2], uint16_t x) {
    out[0] = (uint8_t)(x);
    out[1] = (uint8_t)(x >> 8);
}

/* Deterministically derive a WOTS secret chain element */
static void derive_wots_secret(uint8_t out[WOTS_N],
                               const uint8_t seed[XMSS_SEED_BYTES],
                               uint32_t leaf_idx,
                               uint16_t chain_idx) {
    uint8_t buf[1 + XMSS_SEED_BYTES + 4 + 2];
    size_t pos = 0;
    buf[pos++] = 0x53; /* 'S' domain tag for Secret */
    memcpy(buf + pos, seed, XMSS_SEED_BYTES); pos += XMSS_SEED_BYTES;
    u32le(buf + pos, leaf_idx); pos += 4;
    u16le(buf + pos, chain_idx); pos += 2;
    hash_shake256(buf, pos, out, WOTS_N);
}

/* Build leaf from WOTS pk */
static void wots_pk_to_leaf(const WOTSKey *wots, uint8_t leaf[HASH_SIZE]) {
    uint8_t concat[WOTS_LEN * WOTS_N];
    for (int j = 0; j < WOTS_LEN; j++) {
        memcpy(concat + j * WOTS_N, wots->pk[j], WOTS_N);
    }
    hash_shake256(concat, sizeof(concat), leaf, HASH_SIZE);
}

int xmss_load_state(int *index) {
    FILE *f = fopen(XMSS_STATE_FILE, "rb");
    if (!f) {
        *index = 0;
        return 0;
    }
    if (fread(index, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    fclose(f);
    return 1;
}

int xmss_save_state(int index) {
    FILE *f = fopen(XMSS_STATE_FILE, "wb");
    if (!f) return -1;
    fwrite(&index, sizeof(int), 1, f);
    fclose(f);
    return 0;
}

/* Keygen: derive all WOTS sk from master seed */
void xmss_keygen(XMSSKey *key) {
    csprng_random_bytes(key->seed, XMSS_SEED_BYTES);

    int total_leaves = XMSS_MAX_KEYS;
    for (int i = 0; i < total_leaves; i++) {
        for (int j = 0; j < WOTS_LEN; j++) {
            derive_wots_secret(key->wots_keys[i].sk[j], key->seed, (uint32_t)i, (uint16_t)j);
        }
        wots_compute_pk(&key->wots_keys[i]);
    }

    /* Build leaves */
    uint8_t leaves[XMSS_MAX_KEYS][HASH_SIZE];
    for (int i = 0; i < total_leaves; i++) {
        wots_pk_to_leaf(&key->wots_keys[i], leaves[i]);
    }
    merkle_compute_root(leaves, total_leaves, key->root);
}

// Keygen with a specific seed (for testing or deterministic generation)
void xmss_keygen_seeded(XMSSKey *key, const uint8_t seed[XMSS_SEED_BYTES]) {
    memcpy(key->seed, seed, XMSS_SEED_BYTES);

    int total_leaves = XMSS_MAX_KEYS;
    for (int i = 0; i < total_leaves; i++) {
        for (int j = 0; j < WOTS_LEN; j++) {
            derive_wots_secret(key->wots_keys[i].sk[j], key->seed, (uint32_t)i, (uint16_t)j);
        }
        wots_compute_pk(&key->wots_keys[i]);
    }

    uint8_t leaves[XMSS_MAX_KEYS][HASH_SIZE];
    for (int i = 0; i < total_leaves; i++) {
        uint8_t concat[WOTS_LEN * WOTS_N];
        for (int j = 0; j < WOTS_LEN; j++) {
            memcpy(concat + j * WOTS_N, key->wots_keys[i].pk[j], WOTS_N);
        }
        hash_shake256(concat, sizeof(concat), leaves[i], HASH_SIZE);
    }

    merkle_compute_root(leaves, total_leaves, key->root);
}


/* Internal helper: rebuild all leaves from stored WOTS pk */
static void build_leaves(const XMSSKey *key, uint8_t leaves[XMSS_MAX_KEYS][HASH_SIZE]) {
    for (int i = 0; i < XMSS_MAX_KEYS; i++) {
        wots_pk_to_leaf(&key->wots_keys[i], leaves[i]);
    }
}

/* Manual sign (no state update) */
void xmss_sign_index(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int index) {
    if (index < 0 || index >= XMSS_MAX_KEYS) {
        fprintf(stderr, "xmss_sign_index: invalid index %d\n", index);
        exit(1);
    }
    sig->index = index;
    size_t msg_len = strlen((const char*)msg);
    wots_sign(msg, msg_len, &key->wots_keys[index], &sig->wots_sig);

    uint8_t leaves[XMSS_MAX_KEYS][HASH_SIZE];
    build_leaves(key, leaves);

    uint8_t recomputed_root[HASH_SIZE];
    merkle_auth_path(leaves, XMSS_MAX_KEYS, index, sig->auth_path, recomputed_root);

    if (memcmp(recomputed_root, key->root, HASH_SIZE) != 0) {
        fprintf(stderr, "xmss_sign_index: root mismatch (internal error)\n");
        exit(1);
    }
}

/* Auto sign (loads/advances index; rotates key if exhausted) */
void xmss_sign_auto(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig) {
    int current_index;
    int status = xmss_load_state(&current_index);
    if (status < 0) {
        fprintf(stderr, "Error reading XMSS state file\n");
        exit(1);
    }

    if (current_index >= XMSS_MAX_KEYS) {
        printf("INFO: XMSS leaves exhausted. Generating new keypair...\n");
        xmss_keygen(key);
        if (xmss_save_key(key) != 0) {
            fprintf(stderr, "ERROR: Failed to save new XMSS key.\n");
            exit(1);
        }
        xmss_save_state(0);
        current_index = 0;
    }

    xmss_sign_index(msg, key, sig, current_index);
    xmss_save_state(current_index + 1);
}

/* Verify */
int xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root) {
    size_t msg_len = strlen((const char*)msg);
    int index = sig->index;
    if (index < 0 || index >= XMSS_MAX_KEYS) return 0;

    uint8_t pk_recovered[WOTS_LEN][WOTS_N];
    wots_pk_from_sig(msg, msg_len, &sig->wots_sig, pk_recovered);

    uint8_t leaf[HASH_SIZE];
    {
        uint8_t concat[WOTS_LEN * WOTS_N];
        for (int j = 0; j < WOTS_LEN; j++) {
            memcpy(concat + j * WOTS_N, pk_recovered[j], WOTS_N);
        }
        hash_shake256(concat, sizeof(concat), leaf, HASH_SIZE);
    }

    uint8_t computed_root[HASH_SIZE];
    merkle_root_from_path(leaf, index, sig->auth_path, XMSS_TREE_HEIGHT, computed_root);
    return memcmp(computed_root, root, HASH_SIZE) == 0;
}

/* Legacy wrapper to preserve existing calls */
int xmss_save_key(const XMSSKey *key) {
    return xmss_io_save_key(XMSS_KEY_FILE, key, XMSS_IO_HASH_SHAKE256);
}
int xmss_load_key(XMSSKey *key) {
    return xmss_io_load_key(XMSS_KEY_FILE, key, NULL);
}