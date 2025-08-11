// import standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// import project-specific headers
#include "csprng.h"
#include "benchmark.h"
#include "xmss.h"
#include "xmss_eth.h"
#include "wots.h"
#include "hash.h"
#include "xmss_config.h"
#include "snark_export.h"

// define constants
#define ROOT_FILE "root.hex"
#define SIG_FILE  "sig.bin"

// Global variables for export
XMSSKey global_xmss_key;
XMSSSignature global_last_signature;
uint8_t global_last_root[HASH_SIZE];
uint32_t global_last_index;

// Global parameters for XMSS
static xmss_params g_params;

// Convert bytes to hex string
static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char *hex = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = hex[(in[i] >> 4) & 0xF];
        out[2*i+1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

// Save/load the root hash
static int save_root(const uint8_t *root) {
    FILE *f = fopen(ROOT_FILE, "w");
    if (!f) return 0;
    char hex[HASH_SIZE * 2 + 1];
    bytes_to_hex(root, HASH_SIZE, hex);
    fprintf(f, "%s\n", hex);
    fclose(f);
    return 1;
}

// Load the root hash from a file
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

    // Convert hex string to bytes
    for (size_t i = 0; i < HASH_SIZE; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &root[i]) != 1) return 0;
    }
    return 1;
}

// This function signs a message using XMSS and saves the signature
static int mode_sign(const char *message) {
    XMSSKey key;
    XMSSSignature sig;
    xmss_params params_from_file;

    // Initialize parameters
    int key_loaded = xmss_load_key(&key, &params_from_file);

    // If a key is loaded, we need to verify the parameters match
    if (key_loaded == 1) {
        printf("Key file found!\n");
        if(params_from_file.h != g_params.h || params_from_file.w != g_params.w) {
            fprintf(stderr, "ERROR: Current parameters (h=%d, w=%d) do not match existing key file parameters.\n", g_params.h, g_params.w);
            fprintf(stderr, "Please verify your configuration and delete or move the old key file if you wish to continue with these new parameters.\n");
            return 1; // Throw an error if parameters do not match
        }

        // Check height matches
        if (params_from_file.h <= 0 || params_from_file.h > 32) {
            fprintf(stderr, "Invalid height h=%d. Must be > 0 and <= 32.\n", params_from_file.h);
            fprintf(stderr, "Please verify your configuration and delete or move the old key file if you wish to continue with these new parameters.\n");
            return -1;
        }

        // Check WOTS value matches
        int verify_w = int_log2(params_from_file.w);
        if (verify_w == -1) {
            fprintf(stderr, "Invalid Winternitz parameter w=%d. Must be a power of 2.\n", params_from_file.w);
            fprintf(stderr, "Please verify your configuration and delete or move the old key file if you wish to continue with these new parameters.\n");
            return -1;
        }

    // If no key is loaded, we generate a new key and save it
    } else {
        printf("Generating new XMSS key (h=%d, w=%d)...\n", g_params.h, g_params.w);
        xmss_keygen(&g_params, &key);
        if (xmss_save_key(&key, &g_params) != 0) {
            fprintf(stderr, "Failed to save XMSS key\n");
            return 1;
        }
        xmss_save_state(0);
    }

    // Save the root hash
    if (xmss_alloc_sig(&sig, &g_params) != 0) { fprintf(stderr, "Failed to allocate signature\n"); return 1; }
    xmss_sign_auto(&g_params, (const uint8_t*)message, &key, &sig);

    // Save the signature to a file    
    if (!save_root(key.root)) {
        fprintf(stderr, "Failed to save root hex\n");
        return 1;
    }

    // Save the signature in Ethereum compact format
    if (xmss_eth_save_sig(SIG_FILE, &sig, &g_params) != 0) {
        fprintf(stderr, "Failed to save Ethereum compact signature\n");
        return 1;
    }

    // Set global variables for export
    global_xmss_key = key;
    global_last_signature = sig;
    memcpy(global_last_root, key.root, HASH_SIZE);
    global_last_index = sig.index;
    size_t sigsz = xmss_eth_sig_size(&g_params);

    // Print the signature details
    printf("Message: \"%s\"\n", message);
    printf("Root (public key): ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%02X", key.root[i]);
    printf("\nIndex used: %d\n", sig.index);
    printf("Ethereum compact signature size: %zu bytes\n", sigsz);
    printf("Done.\n");

    xmss_free_sig(&sig, &g_params);
    return 0;
}

// This function verifies a message signature using XMSS.
static int mode_verify(const char *message) {
    XMSSSignature sig;
    uint8_t root[HASH_SIZE];

    // Load the signature file
    if (!load_root(root)) {
        fprintf(stderr, "Missing root.hex\n");
        return 1;
    }
    
    // Get the parameters from the signature file
    xmss_params params_from_file;
    int r = xmss_eth_load_sig(SIG_FILE, &sig, &params_from_file);
    if (r <= 0) {
        fprintf(stderr, "Missing or invalid %s\n", SIG_FILE);
        return 1;
    }

    // Check if the parameters match the expected values
    printf("Loaded signature (h=%d, w=%d, index=%d)\n", params_from_file.h, params_from_file.w, sig.index);
    printf("Verifying message: \"%s\"\n", message);

    // Verify the signature
    int ok = xmss_verify(&params_from_file, (const uint8_t*)message, &sig, root);
    printf(ok ? "Verification SUCCESS\n" : "Verification FAILED\n");
    
    xmss_free_sig(&sig, &g_params);
    return ok ? 0 : 1;
}

// Usage instructions
static void print_usage(const char *prog) {
    printf("Usage: %s [mode] [parameters] [options]\n", prog);
    printf("\nMode:\n");
    printf("  -e \"message\"     # Sign a message\n");
    printf("  -v \"message\"     # Verify a message\n");
    printf("  -b [k s v]         # Benchmark (defaults: k=100, s=1000, v=1000)\n");
    printf("\nBenchmarking Options:\n");
    printf("  [k]                # Number of key generations\n");
    printf("  [s]                # Number of sign operations\n");
    printf("  [v]                # Number of verify operations\n");
    printf("\nParameters (Optional, for use with sign or benchmark):\n");
    printf("  --height <h>       Set XMSS Merkle tree height (Default=5)\n");
    printf("  --wots <w>         Set WOTS+ Winternitz parameter (Default=8, must be to the (Default=5)power of 2)\n");
    printf("  --seed N           Use deterministic RNG seed\n");
    printf("  --export-snark     <filename.json>    Export snark data to specified JSON file (optional)\n");

}

// Main function to handle command line arguments and select modes
int main(int argc, char *argv[]) {
    uint64_t custom_seed = 0;
    bool seed_set = false;
    const char *sign_msg = NULL;
    const char *snark_outfile = NULL;
    char *mode = NULL, *message = NULL;

    // Default parameters
    int h = 5, w = 8;
    int k = 10, s = 100, v = 100;

    // Check for mode flags and parameters
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            mode = "-e";
            sign_msg = argv[++i];

        } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
            mode = "-v";
            message = argv[++i];

        } else if (strcmp(argv[i], "-b") == 0) {
            mode = "-b";

            // Check for optional parameters k, s, v
            if (i + 1 < argc) k = atoi(argv[++i]);
            if (i + 1 < argc) s = atoi(argv[++i]);
            if (i + 1 < argc) v = atoi(argv[++i]);

        // Input validation for height parameter
        } else if (strcmp(argv[i], "--height") == 0 && i + 1 < argc) {
            h = atoi(argv[++i]);
            if (h <= 0) {
                fprintf(stderr, "Error: --height must be a positive integer.\n");
                return 1;
            }

        // Input validation for wots parameter
        } else if (strcmp(argv[i], "--wots") == 0 && i + 1 < argc) {
            w = atoi(argv[++i]);
            if (w < 2) {
                fprintf(stderr, "Error: --wots must be a positive integer greater than or equal to 2.\n");
                return 1;
            }

        // Check if a seed is provided
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (mode == NULL || strcmp(mode, "-e") != 0) {
                fprintf(stderr, "--seed is only allowed with -e\n");
                return 1;
            }
            custom_seed = strtoull(argv[++i], NULL, 10);
            seed_set = true;

        // Check if snark export is required
        } else if (strcmp(argv[i], "--export-snark") == 0 && i + 1 < argc) {
            if (mode == NULL || strcmp(mode, "-e") != 0) {
                fprintf(stderr, "--export-snark is only allowed with -e\n");
                return 1;
            }
            snark_outfile = argv[++i];

        // If input is invalid, print usage
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    // Initalise XMSS parameters
    g_params.h = h;
    g_params.w = w;
    if (xmss_params_init(&g_params, h, w) != 0) {
        return -1;
    }
    
    // Ensure a mode is selected
    if (!mode) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Validate k, s, and v (benchmarking iterations)
    if (k <= 0 || s <= 0 || v <= 0) {
        fprintf(stderr, "Error: [k], [s], and [v] values must be positive integers.\n");
        return 1;
    }

    // Initialize PRF
    if (seed_set) {
        printf("[CSPRNG] Using deterministic seed: %llu\n", (unsigned long long)custom_seed);
        csprng_seed_from_int(custom_seed);
    } else {
        csprng_init(NULL, NULL);
    }
    
    // Signing mode
    if (strcmp(mode, "-e") == 0) {
        if (mode_sign(sign_msg) != 0) {
            fprintf(stderr, "Signing failed.\n");
            return 1;
        }
    
    // Benchmarking mode
    } else if (strcmp(mode, "-b") == 0) {
        run_benchmark(&g_params, k, s, v);
        return 0;
    
    // Verification mode
    } else if (strcmp(mode, "-v") == 0) {
        return mode_verify(message);
    
    // Throw an error if the mode is not recognized
    } else {
        print_usage(argv[0]);
        return -1;
    }

    // Export SNARK if requested
    if (snark_outfile) {
        printf("Exporting SNARK data to %s\n", snark_outfile);
        
        // Throw an error if exporting SNARK fails
        if (export_snark_json(snark_outfile, (const uint8_t*)sign_msg, strlen(sign_msg), h, w) != 0) { 
            fprintf(stderr, "Failed to export SNARK data.\n");
            return 1;
        }
    }

    return 0;
}