#include "xmss.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "csprng.h"

/* --- Memory Management --- */
int xmss_alloc_sig(XMSSSignature *sig, const xmss_params *params) {
    sig->wots_sig = malloc(sizeof(WOTSSignature));
    if (!sig->wots_sig || wots_alloc_sig(sig->wots_sig, params) != 0) {
        free(sig->wots_sig);
        return -1;
    }

    sig->auth_path = malloc(params->h * sizeof(uint8_t*));
    if (!sig->auth_path) {
        wots_free_sig(sig->wots_sig, params);
        free(sig->wots_sig);
        return -1;
    }
    for (int i = 0; i < params->h; i++) {
        sig->auth_path[i] = malloc(HASH_SIZE);
        if (!sig->auth_path[i]) {
            for (int j = 0; j < i; j++) free(sig->auth_path[j]);
            free(sig->auth_path);
            wots_free_sig(sig->wots_sig, params);
            free(sig->wots_sig);
            return -1;
        }
    }
    return 0;
}

void xmss_free_sig(XMSSSignature *sig, const xmss_params *params) {
    if (!sig) return;
    if (sig->auth_path) {
        for (int i = 0; i < params->h; i++) {
            free(sig->auth_path[i]);
        }
        free(sig->auth_path);
    }
    if (sig->wots_sig) {
        wots_free_sig(sig->wots_sig, params);
        free(sig->wots_sig);
    }
}


/* --- Core Functions --- */
// Forward declaration for recursive function
void compute_node(const xmss_params *params, uint8_t *node, XMSSKey *key, int height, uint64_t index);

void compute_node(const xmss_params *params, uint8_t *node, XMSSKey *key, int height, uint64_t index) {
    if (height == 0) {
        WOTSKey wots_key;
        if (wots_alloc_key(&wots_key, params) != 0) abort();
        // Call the function which is now defined in xmss_wots.c
        xmss_generate_wots_key(params, key, index, &wots_key);
        wots_compute_pk(params, &wots_key);
        
        uint8_t *pk_concat = malloc(params->wots_len * HASH_SIZE);
        if(!pk_concat) abort();
        for(int i=0; i<params->wots_len; i++) memcpy(pk_concat + i*HASH_SIZE, wots_key.pk[i], HASH_SIZE);
        hash_shake256(pk_concat, params->wots_len * HASH_SIZE, node, HASH_SIZE);
        
        free(pk_concat);
        wots_free_key(&wots_key, params);
        return;
    }

    uint8_t left[HASH_SIZE], right[HASH_SIZE];
    compute_node(params, left, key, height - 1, index * 2);
    compute_node(params, right, key, height - 1, index * 2 + 1);
    
    uint8_t buffer[2 * HASH_SIZE];
    memcpy(buffer, left, HASH_SIZE);
    memcpy(buffer + HASH_SIZE, right, HASH_SIZE);
    hash_shake256(buffer, 2 * HASH_SIZE, node, HASH_SIZE);
}

void xmss_keygen(const xmss_params *params, XMSSKey *key) {
    csprng_random_bytes(key->seed, XMSS_SEED_BYTES);
    compute_node(params, key->root, key, params->h, 0);
}

void xmss_sign_index(const xmss_params *params, const uint8_t *msg, XMSSKey *key, XMSSSignature *sig, int idx) {
    if (idx < 0 || (uint64_t)idx >= params->max_keys) return;
    
    sig->index = idx;
    
    uint8_t msg_hash[HASH_SIZE];
    hash_shake256(msg, strlen((const char*)msg), msg_hash, HASH_SIZE);
    
    WOTSKey wots_key;
    if (wots_alloc_key(&wots_key, params) != 0) abort();
    // Call the function which is now defined in xmss_wots.c
    xmss_generate_wots_key(params, key, idx, &wots_key);
    
    wots_sign(params, msg_hash, HASH_SIZE, &wots_key, sig->wots_sig);

    // Securely wipe the one-time secret key after use
    for(int i=0; i<params->wots_len; i++) secure_zero_memory(wots_key.sk[i], HASH_SIZE);
    
    uint64_t node_idx = idx;
    for (int h = 0; h < params->h; h++) {
        uint64_t sibling_idx = node_idx ^ 1;
        compute_node(params, sig->auth_path[h], key, h, sibling_idx);
        node_idx >>= 1;
    }

    wots_free_key(&wots_key, params);
}

void xmss_sign_auto(const xmss_params *params, const uint8_t *msg, XMSSKey *key, XMSSSignature *sig) {
    int current_index;
    if (xmss_load_state(&current_index) < 0) {
        fprintf(stderr, "Error reading XMSS state file\n");
        exit(1);
    }

    if ((uint64_t)current_index >= params->max_keys) {
        printf("INFO: XMSS leaves exhausted. Generating new keypair...\n");
        xmss_keygen(params, key);
        if (xmss_save_key(key, params) != 0) {
            fprintf(stderr, "ERROR: Failed to save new XMSS key.\n");
            exit(1);
        }
        current_index = 0;
        xmss_save_state(0);
    }

    xmss_sign_index(params, msg, key, sig, current_index);
    xmss_save_state(current_index + 1);
}

int xmss_verify(const xmss_params *params, const uint8_t *msg, XMSSSignature *sig, const uint8_t *root) {
    uint8_t msg_hash[HASH_SIZE];
    hash_shake256(msg, strlen((const char*)msg), msg_hash, HASH_SIZE);

    WOTSKey wots_pk_from_sig;
    if (wots_alloc_key(&wots_pk_from_sig, params) != 0) abort();
    wots_verify(params, msg_hash, sig->wots_sig, &wots_pk_from_sig);
    
    uint8_t node[HASH_SIZE];
    uint8_t buffer[2 * HASH_SIZE];
    
    uint8_t *pk_concat = malloc(params->wots_len * HASH_SIZE);
    if (!pk_concat) abort();
    for(int i=0; i<params->wots_len; i++) memcpy(pk_concat + i*HASH_SIZE, wots_pk_from_sig.pk[i], HASH_SIZE);
    hash_shake256(pk_concat, params->wots_len * HASH_SIZE, node, HASH_SIZE);
    free(pk_concat);

    uint64_t idx = sig->index;
    for (int h = 0; h < params->h; h++) {
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
    
    wots_free_key(&wots_pk_from_sig, params);
    return memcmp(node, root, HASH_SIZE) == 0;
}

/* --- Persistence --- */
int xmss_save_key(const XMSSKey *key, const xmss_params *params) {
    FILE *f = fopen(XMSS_KEY_FILE, "wb");
    if (!f) return -1;
    // Write params first
    if (fwrite(&params->h, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    if (fwrite(&params->w, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    // Write key data
    if (fwrite(key, sizeof(XMSSKey), 1, f) != 1) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int xmss_load_key(XMSSKey *key, xmss_params *params) {
    FILE *f = fopen(XMSS_KEY_FILE, "rb");
    if (!f) return 0;
    int h, w;
    if (fread(&h, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&w, sizeof(int), 1, f) != 1) { fclose(f); return -1; }

    if (xmss_params_init(params, h, w) != 0) {
        fprintf(stderr, "Failed to init params from key file\n");
        fclose(f);
        return -1;
    }
    
    if (fread(key, sizeof(XMSSKey), 1, f) != 1) { fclose(f); return -1; }
    fclose(f);
    return 1;
}

int xmss_load_state(int *index) {
    FILE *f = fopen(XMSS_STATE_FILE, "rb");
    if (!f) { *index = 0; return 0; }
    if (fread(index, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    fclose(f); return 1;
}

int xmss_save_state(int index) {
    FILE *f = fopen(XMSS_STATE_FILE, "wb");
    if (!f) return -1;
    fwrite(&index, sizeof(int), 1, f);
    fclose(f); return 0;
}

/*
 * NOTE: The implementation for xmss_generate_wots_key is now located
 * exclusively in src/xmss_wots.c to satisfy the user's request.
 */