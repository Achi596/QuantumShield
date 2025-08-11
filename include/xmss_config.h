#ifndef XMSS_CONFIG_H
#define XMSS_CONFIG_H

#include <stdint.h>
#include <stddef.h>

// Struct to hold all runtime-configurable XMSS/WOTS parameters
typedef struct {
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

// Calculate log2 for integer powers of 2
int int_log2(int n);

// Initializes the parameter structure based on h and w.
int xmss_params_init(xmss_params *params, int h, int w);

#endif