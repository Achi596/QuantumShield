#ifndef XMSS_CONFIG_H
#define XMSS_CONFIG_H

#include <stdint.h>
#include <stddef.h>

// Struct to hold all runtime-configurable XMSS/WOTS parameters
typedef struct {
    // Core parameters
    int h;          // XMSS tree height
    int w;          // WOTS+ Winternitz parameter

    // Derived WOTS parameters
    int log_w;      // log2(w)
    int wots_len1;
    int wots_len2;
    int wots_len;   // Total WOTS+ chain length

    // Derived XMSS parameters
    uint64_t max_keys; // 2^h
} xmss_params;

/**
 * @brief Initializes the parameter structure based on h and w.
 * @param params The parameter struct to initialize.
 * @param h The XMSS tree height.
 * @param w The WOTS+ Winternitz parameter (must be a power of 2).
 * @return 0 on success, -1 on failure (e.g., invalid w).
 */
int xmss_params_init(xmss_params *params, int h, int w);

#endif