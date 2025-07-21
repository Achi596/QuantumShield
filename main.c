#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "csprng.h"
#include "benchmark.h"
#include "xmss.h"
#include "xmss_eth.h"
#include "wots.h"
#include "hash.h"

#define ROOT_FILE "root.hex"
#define SIG_FILE  "sig.bin"

/* Convert bytes to hex string */
static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char *hex = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = hex[(in[i] >> 4) & 0xF];
        out[2*i+1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

/* Save/load the root hash */
static int save_root(const uint8_t *root) {
    FILE *f = fopen(ROOT_FILE, "w");
    if (!f) return 0;
    char hex[HASH_SIZE * 2 + 1];
    bytes_to_hex(root, HASH_SIZE, hex);
    fprintf(f, "%s\n", hex);
    fclose(f);
    return 1;
}

/* Load the root hash from file */
static int load_root(uint8_t *root) {
    FILE *f = fopen(ROOT_FILE, "r");
    if (!f) return 0;
    char hex[HASH_SIZE * 2 + 2];
    if (!fgets(hex, sizeof(hex), f)) { fclose(f); return 0; }
    size_t l = strlen(hex);
    if (l && (hex[l-1] == '\n' || hex[l-1] == '\r')) hex[l-1] = '\0';
    fclose(f);

    // Add error checking for hex string length
    if (strlen(hex) != HASH_SIZE * 2) {
        fprintf(stderr, "Invalid root hash length in %s\n", ROOT_FILE);
        return 0;
    }

    for (size_t i = 0; i < HASH_SIZE; i++) {
        int read = sscanf(hex + 2 * i, "%2hhx", &root[i]);
        if (read != 1) {
            fprintf(stderr, "Failed to parse hex at position %zu\n", i);
            return 0;
        }
    }
    return 1;
}

// This function signs a message using XMSS and saves the signature.
static int mode_sign(const char *message) {
    XMSSKey key;
    XMSSSignature sig;

    if (xmss_load_key(&key)) {
        printf("Key file found! loading existing XMSS key...\n");
    } else {
        printf("Generating new XMSS key...\n");
        xmss_keygen(&key);
        if (xmss_save_key(&key) != 0) {
            fprintf(stderr, "Failed to save XMSS key\n");
            return 1;
        }
        xmss_save_state(0);
    }

    xmss_sign_auto((const uint8_t*)message, &key, &sig);

    if (!save_root(key.root)) {
        fprintf(stderr, "Failed to save root hex\n");
        return 1;
    }
    if (xmss_eth_save_sig(SIG_FILE, &sig) != 0) {
        fprintf(stderr, "Failed to save Ethereum compact signature\n");
        return 1;
    }

    size_t sigsz = xmss_eth_sig_size();
    printf("Message: \"%s\"\n", message);
    printf("Root (public key): ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%02X", key.root[i]);
    printf("\nIndex used: %d\n", sig.index);
    printf("Ethereum compact signature size: %zu bytes%s\n",
           sigsz, (sigsz > XMSS_ETH_SIG_MAX_BYTES ? " (WARNING >4k!)" : ""));
    printf("Done.\n");
    return 0;
}


// This function verifies a message signature using XMSS.
static int mode_verify(const char *message) {
    XMSSSignature sig;
    uint8_t root[HASH_SIZE];

    if (!load_root(root)) {
        fprintf(stderr, "Missing root.hex\n");
        return 1;
    }
    printf("Loaded root: ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%02X", root[i]);
    printf("\n");

    size_t sig_len = 0;
    int r = xmss_eth_load_sig(SIG_FILE, &sig, &sig_len);
    if (r <= 0) {
        fprintf(stderr, "Missing or invalid %s\n", SIG_FILE);
        return 1;
    }
    printf("Loaded signature (index=%d, len=%zu)\n", sig.index, sig_len);
    printf("Message to verify: \"%s\"\n", message);

    int ok = xmss_verify((const uint8_t*)message, &sig, root);
    printf(ok ? "Verification SUCCESS\n" : "Verification FAILED\n");
    return ok ? 0 : 1;
}


/* Usage instructions */
static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s [--seed N] -e \"message\"   # sign message\n", prog);
    printf("  %s [--seed N] -v \"message\"   # verify message\n", prog);
    printf("  %s [--seed N] -b [k s v]      # benchmark (defaults 100 1000 1000)\n", prog);
}

/* Run benchmarks */
int main(int argc, char *argv[]) {
    int arg_index = 1;
    uint64_t custom_seed = 0;
    int seed_set = 0;

    // Check for --seed option
    if (argc > 2 && strcmp(argv[1], "--seed") == 0) {
        custom_seed = strtoull(argv[2], NULL, 10);
        seed_set = 1;
        arg_index = 3;  // Skip these two arguments
    }

    if (seed_set) {
        printf("[CSPRNG] Using deterministic seed: %llu\n", (unsigned long long)custom_seed);
        csprng_seed_from_int(custom_seed);
    } else {
        csprng_init(NULL, NULL); // default random seed
    }

    if (arg_index >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[arg_index], "-e") == 0 && arg_index + 1 < argc) {
        return mode_sign(argv[arg_index + 1]);
    } else if (strcmp(argv[arg_index], "-v") == 0 && arg_index + 1 < argc) {
        return mode_verify(argv[arg_index + 1]);
    } else if (strcmp(argv[arg_index], "-b") == 0) {
        int k = 10, s = 100, v = 100;
        if (arg_index + 1 < argc) k = atoi(argv[arg_index + 1]);
        if (arg_index + 2 < argc) s = atoi(argv[arg_index + 2]);
        if (arg_index + 3 < argc) v = atoi(argv[arg_index + 3]);
        if (k <= 0) k = 1;
        if (s <= 0) s = 1;
        if (v <= 0) v = 1;
        run_benchmark(k, s, v);
        return 0;
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
