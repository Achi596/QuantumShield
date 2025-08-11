// Import standard libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Import project-specific headers
#include "timer.h"
#include "wots.h"
#include "xmss_config.h"
#include "hash.h"
#include "csprng.h"

#define NUM_RUNS 10000 // Number of iterations to average over

// This test measures and compares the timing of a hardened (constant-time)
// vs. a vulnerable (variable-time) signing function.
int main() {
    xmss_params params;
    // We use w=16 as it's a common choice and will show a clear timing difference.
    if (xmss_params_init(&params, 4, 16) != 0) {
        return 1;
    }
    printf("Running timing comparison for WOTS+ (w=%d) over %d iterations...\n", params.w, NUM_RUNS);

    // --- Prepare Keys and Messages ---
    csprng_init(NULL, NULL);
    WOTSKey key;
    WOTSSignature sig;
    if (wots_alloc_key(&key, &params) != 0 || wots_alloc_sig(&sig, &params) != 0) {
        fprintf(stderr, "Allocation failed\n");
        return 1;
    }

    // Generate a random WOTS secret key
    for (int i = 0; i < params.wots_len; i++) {
        csprng_random_bytes(key.sk[i], HASH_SIZE);
    }

    // Create two "extreme" messages.
    // "Easy" message: all zeros, results in low base-w digits, few hash operations in vulnerable code.
    uint8_t msg_easy[HASH_SIZE];
    memset(msg_easy, 0x00, HASH_SIZE);

    // "Hard" message: all 0xFF, results in high base-w digits, many hash operations in vulnerable code.
    uint8_t msg_hard[HASH_SIZE];
    memset(msg_hard, 0xFF, HASH_SIZE);

    // Initialize timer variables
    double start, end;
    double time_hardened_easy = 0, time_hardened_hard = 0;
    double time_vulnerable_easy = 0, time_vulnerable_hard = 0;

    // --- Test Hardened (Constant-Time) Function ---
    for (int i = 0; i < NUM_RUNS; i++) {
        start = hires_time_seconds();
        wots_sign(&params, msg_easy, HASH_SIZE, &key, &sig);
        end = hires_time_seconds();
        time_hardened_easy += (end - start);

        start = hires_time_seconds();
        wots_sign(&params, msg_hard, HASH_SIZE, &key, &sig);
        end = hires_time_seconds();
        time_hardened_hard += (end - start);
    }

    // --- Test Vulnerable (Variable-Time) Function ---
    for (int i = 0; i < NUM_RUNS; i++) {
        start = hires_time_seconds();
        wots_sign_vulnerable(&params, msg_easy, HASH_SIZE, &key, &sig);
        end = hires_time_seconds();
        time_vulnerable_easy += (end - start);

        start = hires_time_seconds();
        wots_sign_vulnerable(&params, msg_hard, HASH_SIZE, &key, &sig);
        end = hires_time_seconds();
        time_vulnerable_hard += (end - start);
    }

    // --- Print Results ---
    printf("\n--- Results (Average Time per Signature) ---\n");
    printf("[Hardened Function (wots_sign)]\n");
    printf("  - 'Easy' Message (low digits):  %.12f s\n", time_hardened_easy / NUM_RUNS);
    printf("  - 'Hard' Message (high digits): %.12f s\n", time_hardened_hard / NUM_RUNS);
    printf("\n");
    printf("[Vulnerable Function (wots_sign_vulnerable)]\n");
    printf("  - 'Easy' Message (low digits):  %.12f s\n", time_vulnerable_easy / NUM_RUNS);
    printf("  - 'Hard' Message (high digits): %.12f s\n", time_vulnerable_hard / NUM_RUNS);
    printf("\n");

    // Calculate the differences
    double diff_hardened = (time_hardened_hard - time_hardened_easy) / NUM_RUNS;
    double diff_vulnerable = (time_vulnerable_hard - time_vulnerable_easy) / NUM_RUNS;

    // Print the final analysis
    printf("--- Analysis ---\n");
    printf("Time difference in HARDENED version:   %.12f s\n", diff_hardened);
    printf("Time difference in VULNERABLE version: %.12f s\n", diff_vulnerable);
    if (diff_vulnerable > diff_hardened * 10) { // Check for significant difference
        printf("\nConclusion: The hardened function shows almost no timing difference between easy and hard messages.\n");
        printf("The vulnerable function is significantly faster for the 'easy' message, leaking timing information.\n");
        printf("Side-channel hardening is working as expected.\n");
    } else {
        printf("\nConclusion: The timing difference is not pronounced. This could be due to system noise or timer resolution.\n");
        printf("Try increasing NUM_RUNS for a more stable average.\n");
    }

    wots_free_key(&key, &params);
    wots_free_sig(&sig, &params);

    return 0;
}