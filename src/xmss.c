#include <string.h>
#include <stdio.h>
#include <stdlib.h> 
#include "xmss.h"
#include "wots.h"
#include "hash.h"
#include "merkle.h"

/* Hash a full WOTS public key (concatenated chains) into a leaf */
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
    if (fread(index, sizeof(int), 1, f) != 1) {
        fclose(f);
        return -1;
    }
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

void xmss_keygen(XMSSKey *key) {
    int total_leaves = 1 << XMSS_TREE_HEIGHT;
    for (int i = 0; i < total_leaves; i++) {
        wots_gen_keypair(&key->wots_keys[i]);
    }

    // Build leaves
    uint8_t leaves[1 << XMSS_TREE_HEIGHT][HASH_SIZE];
    for (int i = 0; i < total_leaves; i++) {
        wots_pk_to_leaf(&key->wots_keys[i], leaves[i]);
    }

    // Compute root
    merkle_compute_root(leaves, total_leaves, key->root);
}

/* Internal helper: build leaves array */
static void build_leaves(const XMSSKey *key, uint8_t leaves[XMSS_MAX_KEYS][HASH_SIZE]) {
    for (int i = 0; i < XMSS_MAX_KEYS; i++) {
        uint8_t concat[WOTS_LEN * WOTS_N];
        for (int j = 0; j < WOTS_LEN; j++) {
            memcpy(concat + j * WOTS_N, key->wots_keys[i].pk[j], WOTS_N);
        }
        hash_shake256(concat, sizeof(concat), leaves[i], HASH_SIZE);
    }
}

/* Manual sign: DOES NOT update persistent state */
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

/* Auto sign: loads & advances persistent index, also has auto key rotation*/
void xmss_sign_auto(const uint8_t *msg, XMSSKey *key, XMSSSignature *sig) {
    int current_index;
    int status = xmss_load_state(&current_index);
    if (status < 0) {
        fprintf(stderr, "Error reading XMSS state file\n");
        exit(1);
    }

    /* Check if key is exhausted */
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

    /* Sign with the current index */
    xmss_sign_index(msg, key, sig, current_index);

    /* Increment and save new index */
    xmss_save_state(current_index + 1);
}

int xmss_verify(const uint8_t *msg, XMSSSignature *sig, const uint8_t *root) {
    size_t msg_len = strlen((const char*)msg);
    int total_leaves = 1 << XMSS_TREE_HEIGHT;
    int index = sig->index;
    if (index < 0 || index >= total_leaves) {
        return 0;
    }

    // Recover WOTS+ public key from signature
    uint8_t pk_recovered[WOTS_LEN][WOTS_N];
    wots_pk_from_sig(msg, msg_len, &sig->wots_sig, pk_recovered);

    // Hash recovered public key into its leaf hash
    uint8_t leaf[HASH_SIZE];
    {
        uint8_t concat[WOTS_LEN * WOTS_N];
        for (int j = 0; j < WOTS_LEN; j++) {
            memcpy(concat + j * WOTS_N, pk_recovered[j], WOTS_N);
        }
        hash_shake256(concat, sizeof(concat), leaf, HASH_SIZE);
    }

    // Reconstruct root from leaf + auth path
    uint8_t computed_root[HASH_SIZE];
    merkle_root_from_path(leaf, index, sig->auth_path, XMSS_TREE_HEIGHT, computed_root);

    // Compare to claimed root
    return memcmp(computed_root, root, HASH_SIZE) == 0;
}

int xmss_save_key(const XMSSKey *key) {
    FILE *f = fopen(XMSS_KEY_FILE, "wb");
    if (!f) {
        perror("xmss_save_key fopen");
        return -1;
    }
    if (fwrite(key, sizeof(XMSSKey), 1, f) != 1) {
        perror("xmss_save_key fwrite");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int xmss_load_key(XMSSKey *key) {
    FILE *f = fopen(XMSS_KEY_FILE, "rb");
    if (!f) return 0; // No key file found
    if (fread(key, sizeof(XMSSKey), 1, f) != 1) {
        perror("xmss_load_key fread");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 1;
}
