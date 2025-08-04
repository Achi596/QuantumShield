#include <string.h>
#include "xmss.h"
#include "hash.h"
#include "xmss_config.h"
#include "util.h"
#include <stdlib.h>

/**
 * @brief Generates a WOTS+ key pair for a specific leaf index.
 * 
 * This function uses the master seed from the XMSSKey and the leaf index
 * to deterministically generate the WOTS+ secret key via a Pseudorandom
 * Function (PRF), which is implemented here using SHAKE256.
 * The corresponding public key is then computed from the secret key.
 *
 * @param params    A pointer to the XMSS/WOTS runtime parameters.
 * @param key       A pointer to the master XMSSKey containing the seed.
 * @param index     The leaf index for which to generate the WOTS+ key.
 * @param wots_key  A pointer to the WOTSKey structure to be filled.
 */
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