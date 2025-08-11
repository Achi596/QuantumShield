// Import standard libraries
#include <string.h>
#include <stdlib.h>

// import project-specific headers
#include "xmss.h"
#include "hash.h"
#include "xmss_config.h"
#include "util.h"

// Generate a WOTS+ key for a specific leaf index
void xmss_generate_wots_key(const xmss_params *params, XMSSKey *key, int index, WOTSKey *wots_key) {
    // Buffer to hold the PRF input: master_seed || leaf_index
    uint8_t buffer[XMSS_SEED_BYTES + sizeof(int)];
    
    // Combine master seed and index to create unique input for each leaf
    memcpy(buffer, key->seed, XMSS_SEED_BYTES);
    memcpy(buffer + XMSS_SEED_BYTES, &index, sizeof(int));
    
    // Allocate a temporary buffer to hold the full concatenated secret key
    size_t sk_total_bytes = (size_t)params->wots_len * HASH_SIZE;
    uint8_t *sk_concat = malloc(sk_total_bytes);
    if (!sk_concat) {
        // In a real application, handle this error more gracefully
        abort();
    }
    
    // Use SHAKE256 as a PRF to generate the entire WOTS+ secret key material
    hash_shake256(buffer, sizeof(buffer), sk_concat, sk_total_bytes);
    
    // Distribute the generated material into the individual secret key chains
    for(int i = 0; i < params->wots_len; i++) {
        memcpy(wots_key->sk[i], sk_concat + (size_t)i * HASH_SIZE, HASH_SIZE);
    }
    
    // Securely wipe the temporary buffers that held sensitive data
    secure_zero_memory(sk_concat, sk_total_bytes);
    secure_zero_memory(buffer, sizeof(buffer));
    free(sk_concat);
    
    // Compute the corresponding public key from the newly generated secret key
    wots_compute_pk(params, wots_key);
}