#include "xmss.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "wots.h"
#include "hash.h"
#include "merkle.h"
#include "csprng.h"
#include "xmss_eth.h"

/* Remove unused static functions */
void compute_node(uint8_t *node, XMSSKey *key, int height, uint64_t index) {
    if (height == 0) {
        // Leaf node - generate WOTS key and compute public key
        WOTSKey wots_key;
        xmss_generate_wots_key(key, index, &wots_key);
        wots_compute_pk(&wots_key);
        hash_shake256((uint8_t*)wots_key.pk, WOTS_N * WOTS_LEN, node, HASH_SIZE);
        return;
    }

    // Internal node - compute children and hash
    uint8_t left[HASH_SIZE], right[HASH_SIZE];
    compute_node(left, key, height - 1, index * 2);
    compute_node(right, key, height - 1, index * 2 + 1);
    
    uint8_t buffer[2 * HASH_SIZE];
    memcpy(buffer, left, HASH_SIZE);
    memcpy(buffer + HASH_SIZE, right, HASH_SIZE);
    hash_shake256(buffer, 2 * HASH_SIZE, node, HASH_SIZE);
}

/* Load XMSS key from file */
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

/* Save XMSS key state to file */
int xmss_save_state(int index) {
    FILE *f = fopen(XMSS_STATE_FILE, "wb");
    if (!f) return -1;
    fwrite(&index, sizeof(int), 1, f);
    fclose(f);
    return 0;
}

/* Keygen: derive all WOTS sk from master seed */
void xmss_keygen(XMSSKey *key) {
    // Generate random seed
    csprng_random_bytes(key->seed, XMSS_SEED_BYTES);
    
    // Compute root node
    compute_node(key->root, key, XMSS_TREE_HEIGHT, 0);
}

/* Keygen with seeded PRF */
void xmss_sign_index(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int idx) {
    if (idx < 0 || idx >= XMSS_MAX_KEYS) return;
    
    sig->index = idx;
    
    // Hash message
    uint8_t msg_hash[HASH_SIZE];
    hash_shake256(msg, strlen((const char*)msg), msg_hash, HASH_SIZE);
    
    // Generate WOTS key for this index
    WOTSKey wots_key;
    xmss_generate_wots_key(key, idx, &wots_key);
    wots_compute_pk(&wots_key);
    
    // Sign message with WOTS
    wots_sign(msg_hash, HASH_SIZE, &wots_key, &sig->wots_sig);
    
    uint8_t leaf[HASH_SIZE];
    hash_shake256((uint8_t*)wots_key.pk, WOTS_LEN * WOTS_N, leaf, HASH_SIZE);
    
    // Compute authentication path
    uint64_t node_idx = idx;
    for (int h = 0; h < XMSS_TREE_HEIGHT; h++) {
        uint64_t sibling_idx = node_idx ^ 1;
        compute_node(sig->auth_path[h], key, h, sibling_idx);
        node_idx >>= 1;
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
    uint8_t msg_hash[HASH_SIZE];
    hash_shake256(msg, strlen((const char*)msg), msg_hash, HASH_SIZE);

    // Generate WOTS public key from signature
    WOTSKey wots_pk;
    wots_verify(msg_hash, &sig->wots_sig, &wots_pk);
    
    // Compute root from signature path
    uint8_t node[HASH_SIZE];
    uint8_t buffer[2 * HASH_SIZE];
    
    // Hash WOTS public key to get leaf node
    hash_shake256((uint8_t*)wots_pk.pk, WOTS_N * WOTS_LEN, node, HASH_SIZE);
    
    // Compute root using authentication path
    uint64_t idx = sig->index;
    for (int h = 0; h < XMSS_TREE_HEIGHT; h++) {
        if (idx & 1) {
            memcpy(buffer, sig->auth_path[h], HASH_SIZE);
            memcpy(buffer + HASH_SIZE, node, HASH_SIZE);
        } else {
            memcpy(buffer, node, HASH_SIZE);
            memcpy(buffer + HASH_SIZE, sig->auth_path[h], HASH_SIZE);
        }
        hash_shake256(buffer, 2 * HASH_SIZE, node, HASH_SIZE);
        idx >>= 1;
    }

    return memcmp(node, root, HASH_SIZE) == 0;
}

/* Save raw XMSSKey structure to disk */
int xmss_save_key(const XMSSKey *key) {
    FILE *f = fopen(XMSS_KEY_FILE, "wb");
    if (!f) return -1;
    if (fwrite(key, sizeof(XMSSKey), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* Load raw XMSSKey structure from disk */
int xmss_load_key(XMSSKey *key) {
    FILE *f = fopen(XMSS_KEY_FILE, "rb");
    if (!f) return 0;  /* Key file doesn't exist */
    size_t read = fread(key, 1, sizeof(XMSSKey), f);
    fclose(f);
    return (read == sizeof(XMSSKey)) ? 1 : -1;
}