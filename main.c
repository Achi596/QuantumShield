#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "xmss.h"
#include "wots.h"
#include "hash.h"
#include "benchmark.h"
#include "csprng.h"

#define SIG_FILE  "sig.bin"
#define ROOT_FILE "root.hex"

/* ========== Utility: hex encode ========== */
static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char *hex = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = hex[(in[i] >> 4) & 0xF];
        out[2*i+1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

/* ========== Persistence Helpers ========== */
static int save_root(const uint8_t *root) {
    FILE *f = fopen(ROOT_FILE, "w");
    if (!f) return 0;
    char hex[HASH_SIZE*2 + 1];
    bytes_to_hex(root, HASH_SIZE, hex);
    fprintf(f, "%s\n", hex);
    fclose(f);
    return 1;
}

static int load_root(uint8_t *root) {
    FILE *f = fopen(ROOT_FILE, "r");
    if (!f) return 0;
    char hex[HASH_SIZE*2 + 2];
    if (!fgets(hex, sizeof(hex), f)) { fclose(f); return 0; }
    size_t l = strlen(hex);
    if (l && (hex[l-1] == '\n' || hex[l-1] == '\r')) hex[l-1] = '\0';
    fclose(f);
    for (size_t i = 0; i < HASH_SIZE; i++) {
        sscanf(hex + 2*i, "%2hhx", &root[i]);
    }
    return 1;
}

static int save_sig(const XMSSSignature *sig) {
    FILE *f = fopen(SIG_FILE, "wb");
    if (!f) return 0;
    fwrite(sig, sizeof(XMSSSignature), 1, f);
    fclose(f);
    return 1;
}

static int load_sig(XMSSSignature *sig) {
    FILE *f = fopen(SIG_FILE, "rb");
    if (!f) return 0;
    fread(sig, sizeof(XMSSSignature), 1, f);
    fclose(f);
    return 1;
}

/* ========== Modes ========== */
static int mode_sign(const char *message) {
    XMSSKey key;
    XMSSSignature sig;

    int key_status = xmss_load_key(&key);
    if (key_status <= 0) {
        printf("No existing key found. Generating new XMSS key...\n");
        xmss_keygen(&key);
        if (xmss_save_key(&key) != 0) {
            fprintf(stderr, "Error saving XMSS key.\n");
            return 1;
        }
        xmss_save_state(0); // Reset index
    } else {
        printf("Key file found! loading existing XMSS key...\n");
    }

    xmss_sign_auto((const uint8_t*)message, &key, &sig);

    save_root(key.root);
    save_sig(&sig);

    printf("Message: \"%s\"\n", message);
    printf("Root (public key): ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%02X", key.root[i]);
    printf("\nIndex used: %d\nDone.\n", sig.index);

    return 0;
}

static int mode_verify(const char *message) {
    XMSSSignature sig;
    uint8_t root[HASH_SIZE];
    if (!load_root(root) || !load_sig(&sig)) {
        fprintf(stderr, "Missing root.hex or sig.bin\n");
        return 1;
    }
    int ok = xmss_verify((const uint8_t*)message, &sig, root);
    printf(ok ? "✅ Verification SUCCESS\n" : "❌ Verification FAILED\n");
    return ok ? 0 : 1;
}

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s -e \"message\"          # sign\n", prog);
    printf("  %s -v \"message\"          # verify\n", prog);
    printf("  %s -b [k s v]             # benchmark (defaults 100 1000 1000)\n", prog);
    benchmark_print_csv_hint();
}

/* ========== main ========== */
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
        int k = 100, s = 1000, v = 1000;
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
