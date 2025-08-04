#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "csprng.h"
#include "benchmark.h"
#include "xmss.h"
#include "xmss_eth.h"
#include "wots.h"
#include "hash.h"
#include "xmss_config.h"

#define ROOT_FILE "root.hex"
#define SIG_FILE  "sig.bin"

// Global params, initialized based on CLI args
static xmss_params g_params;

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
        if (sscanf(hex + 2 * i, "%2hhx", &root[i]) != 1) return 0;
    }
    return 1;
}

// This function signs a message using XMSS and saves the signature.
static int mode_sign(const char *message) {
    XMSSKey key;
    XMSSSignature sig;
    xmss_params params_from_file;

    int key_loaded = xmss_load_key(&key, &params_from_file);

    if (key_loaded) {
        printf("Key file found! loading existing XMSS key (h=%d, w=%d)...\n", params_from_file.h, params_from_file.w);
        if(params_from_file.h != g_params.h || params_from_file.w != g_params.w) {
            fprintf(stderr, "ERROR: CLI parameters (h=%d, w=%d) do not match key file parameters.\n", g_params.h, g_params.w);
            return 1;
        }
    } else {
        printf("Generating new XMSS key (h=%d, w=%d)...\n", g_params.h, g_params.w);
        xmss_keygen(&g_params, &key);
        if (xmss_save_key(&key, &g_params) != 0) {
            fprintf(stderr, "Failed to save XMSS key\n");
            return 1;
        }
        xmss_save_state(0);
    }
    
    if (xmss_alloc_sig(&sig, &g_params) != 0) { fprintf(stderr, "Failed to allocate signature\n"); return 1; }
    xmss_sign_auto(&g_params, (const uint8_t*)message, &key, &sig);

    if (!save_root(key.root)) {
        fprintf(stderr, "Failed to save root hex\n");
        xmss_free_sig(&sig, &g_params);
        return 1;
    }
    if (xmss_eth_save_sig(SIG_FILE, &sig, &g_params) != 0) {
        fprintf(stderr, "Failed to save Ethereum compact signature\n");
        xmss_free_sig(&sig, &g_params);
        return 1;
    }
    
    size_t sigsz = xmss_eth_sig_size(&g_params);
    printf("Message: \"%s\"\n", message);
    printf("Root (public key): ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%02X", key.root[i]);
    printf("\nIndex used: %d\n", sig.index);
    printf("Ethereum compact signature size: %zu bytes\n", sigsz);
    
    xmss_free_sig(&sig, &g_params);
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
    
    // The params will be loaded from the signature file
    xmss_params params_from_file;
    int r = xmss_eth_load_sig(SIG_FILE, &sig, &params_from_file);
    if (r <= 0) {
        fprintf(stderr, "Missing or invalid %s\n", SIG_FILE);
        return 1;
    }
    printf("Loaded signature (h=%d, w=%d, index=%d)\n", params_from_file.h, params_from_file.w, sig.index);
    printf("Verifying message: \"%s\"\n", message);

    int ok = xmss_verify(&params_from_file, (const uint8_t*)message, &sig, root);
    printf(ok ? "Verification SUCCESS\n" : "Verification FAILED\n");
    
    xmss_free_sig(&sig, &params_from_file);
    return ok ? 0 : 1;
}

/* Usage instructions */
static void print_usage(const char *prog) {
    printf("Usage: %s [params] [options]\n", prog);
    printf("\nParameters (Required for sign/benchmark, optional for verify):\n");
    printf("  --height <h>      Set XMSS Merkle tree height\n");
    printf("  --wots <w>        Set WOTS+ Winternitz parameter (power of 2)\n");
    printf("\nOptions:\n");
    printf("  -e \"message\"      Sign message\n");
    printf("  -v \"message\"      Verify message\n");
    printf("  -b [k s v]        Benchmark (keygen, sign, verify runs)\n");
    printf("  --seed N          Use deterministic RNG seed\n");
}

/* Run benchmarks */
int main(int argc, char *argv[]) {
    int h = 0, w = 0;
    uint64_t custom_seed = 0;
    bool seed_set = false;
    char *mode = NULL, *message = NULL;
    int bench_k = 10, bench_s = 100, bench_v = 100;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--height") == 0 && i + 1 < argc) {
            h = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--wots") == 0 && i + 1 < argc) {
            w = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            custom_seed = strtoull(argv[++i], NULL, 10);
            seed_set = true;
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            mode = "-e"; message = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
            mode = "-v"; message = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0) {
            mode = "-b";
            if (i + 1 < argc && argv[i+1][0] != '-') bench_k = atoi(argv[++i]);
            if (i + 1 < argc && argv[i+1][0] != '-') bench_s = atoi(argv[++i]);
            if (i + 1 < argc && argv[i+1][0] != '-') bench_v = atoi(argv[++i]);
        } else {
             print_usage(argv[0]); return 1;
        }
    }
    
    if (!mode) {
        print_usage(argv[0]);
        return 1;
    }
    
    if (strcmp(mode, "-v") != 0) { // Sign and benchmark modes require params
        if (h == 0 || w == 0) {
            fprintf(stderr, "Error: --height and --wots parameters are required for this mode.\n\n");
            print_usage(argv[0]);
            return 1;
        }
        if (xmss_params_init(&g_params, h, w) != 0) {
            return 1;
        }
    }

    if (seed_set) {
        printf("[CSPRNG] Using deterministic seed: %llu\n", (unsigned long long)custom_seed);
        csprng_seed_from_int(custom_seed);
    } else {
        csprng_init(NULL, NULL);
    }
    
    if (strcmp(mode, "-e") == 0) {
        return mode_sign(message);
    } else if (strcmp(mode, "-v") == 0) {
        return mode_verify(message);
    } else if (strcmp(mode, "-b") == 0) {
        if (bench_k <= 0) bench_k = 1;
        if (bench_s <= 0) bench_s = 1;
        if (bench_v <= 0) bench_v = 1;
        run_benchmark(&g_params, bench_k, bench_s, bench_v);
        return 0;
    } else {
        print_usage(argv[0]);
        return 1;
    }
}