#include <string.h>
#include "xmss.h"
#include "hash.h"

/* New helper function to generate WOTS key for specific index */
void xmss_generate_wots_key(XMSSKey *key, int index, WOTSKey *wots_key) {
    uint8_t buffer[XMSS_SEED_BYTES + sizeof(int)];
    
    // Combine master seed and index
    memcpy(buffer, key->seed, XMSS_SEED_BYTES);
    memcpy(buffer + XMSS_SEED_BYTES, &index, sizeof(int));
    
    // Generate WOTS private key using PRF
    hash_shake256(buffer, sizeof(buffer), 
                 (uint8_t*)wots_key->sk, 
                 WOTS_N * WOTS_LEN);
                 
    // Compute corresponding public key
    wots_compute_pk(wots_key);
}