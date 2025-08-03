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
#include "snark_export.h"

#define ROOT_FILE "root.hex"
#define SIG_FILE  "sig.bin"

XMSSKey global_xmss_key;
XMSSSignature global_last_signature;
uint8_t global_last_root[HASH_SIZE];
uint32_t global_last_index;

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

    // Convert hex string back to bytes
    for (size_t i = 0; i < HASH_SIZE; i++) {
        int read = sscanf(hex + 2 * i, "%2hhx", &root[i]);
        if (read != 1) {
            fprintf(stderr, "Failed to parse hex at position %zu\n", i);
            return 0;
        }
    }
    return 1;
}

/* Sign a message using XMSS */
static int mode_sign(const char *message) {
    XMSSKey key;
    XMSSSignature sig;

    // Initialize XMSS key
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

    // Sign the message
    xmss_sign_auto((const uint8_t*)message, &key, &sig);

    // Save the signature
    if (!save_root(key.root)) {
        fprintf(stderr, "Failed to save root hex\n");
        return 1;
    }

    // Verify the signature size is below the 4096 bytes limit
    if (xmss_eth_save_sig(SIG_FILE, &sig) != 0) {
        fprintf(stderr, "Failed to save Ethereum compact signature\n");
        return 1;
    }

    // Set global variables for export
    global_xmss_key = key;
    global_last_signature = sig;
    memcpy(global_last_root, key.root, HASH_SIZE);
    global_last_index = sig.index;

    // Print summary
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

    // Load the root hash
    if (!load_root(root)) {
        fprintf(stderr, "Missing root.hex\n");
        return 1;
    }

    // Print the loaded root
    printf("Loaded root: ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%02X", root[i]);
    printf("\n");

    // Load the signature
    size_t sig_len = 0;
    int r = xmss_eth_load_sig(SIG_FILE, &sig, &sig_len);
    if (r <= 0) {
        fprintf(stderr, "Missing or invalid %s\n", SIG_FILE);
        return 1;
    }

    // Print the loaded signature
    printf("Loaded signature (index=%d, len=%zu)\n", sig.index, sig_len);
    printf("Message to verify: \"%s\"\n", message);

    // Verify the signature
    int ok = xmss_verify((const uint8_t*)message, &sig, root);
    printf(ok ? "Verification SUCCESS\n" : "Verification FAILED\n");
    return ok ? 0 : 1;
}


/* Usage instructions */
static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s [--seed N] -e \"message\"     # Sign a message\n", prog);
    printf("  %s [--seed N] -v \"message\"     # Verify a message\n", prog);
    printf("  %s [--seed N] -b [k s v]       # Benchmark (defaults: k=100, s=1000, v=1000)\n", prog);
    printf("\n");
    printf("Parameters:\n");
    printf("  k - number of key generations\n");
    printf("  s - number of sign operations\n");
    printf("  v - number of verify operations\n");
    printf("\n");
    printf("Options:\n");
    printf("  --seed N                          Seed value for key generation (optional)\n");
    printf("  --export-snark <filename.json>    Export snark data to specified JSON file (optional)\n");
}


/* Run benchmarks */
int main(int argc, char *argv[]) {
    uint64_t custom_seed = 0;
    int seed_set = 0;
    const char *sign_msg = NULL;
    const char *snark_outfile = NULL;

    // Check for no arguments
    if (argc == 1) {
    print_usage(argv[0]);
    return 1;
    }

    // Parse all args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            custom_seed = strtoull(argv[++i], NULL, 10);
            seed_set = 1;
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            sign_msg = argv[++i];
        } else if (strcmp(argv[i], "--export-snark") == 0 && i + 1 < argc) {
            snark_outfile = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
            return mode_verify(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0) {
            int k = 10, s = 100, v = 100;
            if (i + 1 < argc) k = atoi(argv[++i]);
            if (i + 1 < argc) s = atoi(argv[++i]);
            if (i + 1 < argc) v = atoi(argv[++i]);
            run_benchmark(k, s, v);
            return 0;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    // Initialize RNG
    if (seed_set) {
        printf("[CSPRNG] Using deterministic seed: %llu\n", (unsigned long long)custom_seed);
        csprng_seed_from_int(custom_seed);
    } else {
        csprng_init(NULL, NULL);
    }

    // Perform signing if requested
    if (sign_msg) {
        if (mode_sign(sign_msg) != 0) {
            fprintf(stderr, "Signing failed.\n");
            return 1;
        }
    }

    // Export SNARK JSON if requested
    if (snark_outfile) {
        if (export_snark_json(snark_outfile, (const uint8_t*)sign_msg, strlen(sign_msg)) == 0) {
            printf("Exporting SNARK data to %s\n", snark_outfile);
        } else {
            fprintf(stderr, "Failed to export SNARK data.\n");
            return 1;
        }
    }

    return 0;
}
