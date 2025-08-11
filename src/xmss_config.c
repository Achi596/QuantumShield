// import standard libraries
#include <stdio.h>
#include <math.h>

// import project-specific headers
#include "xmss_config.h"
#include "hash.h"

// Helper to calculate log2 for integer powers of 2
int int_log2(int n) {
    if (n <= 0) return -1;
    int log = 0;
    while ((1 << log) < n) {
        log++;
    }
    if ((1 << log) != n) return -1; // Not a power of 2
    return log;
}

// Initialize XMSS parameters
int xmss_params_init(xmss_params *params, int h, int w) {
    if (h <= 0 || h > 32) {
        fprintf(stderr, "Invalid height h=%d. Must be > 0 and <= 32.\n", h);
        return -1;
    }
    params->h = h;
    params->max_keys = 1ULL << h;

    params->log_w = int_log2(w);
    if (params->log_w == -1) {
        fprintf(stderr, "Invalid Winternitz parameter w=%d. Must be a power of 2.\n", w);
        return -1;
    }
    params->w = w;

    // Calculate WOTS+ lengths
    params->wots_len1 = (8 * HASH_SIZE) / params->log_w;
    int checksum_bits = params->wots_len1 * (w - 1);
    int checksum_log = 0;
    if (checksum_bits > 0) {
        checksum_log = (int)floor(log2(checksum_bits)) + 1;
    }
    params->wots_len2 = (checksum_log + params->log_w - 1) / params->log_w;
    params->wots_len = params->wots_len1 + params->wots_len2;

    return 0;
}