#ifndef XMSS_ETH_H
#define XMSS_ETH_H

#include <stddef.h>
#include <stdint.h>
#include "xmss.h"
#include "xmss_config.h"

/**
 * @brief Compute the serialized signature size for the given XMSS/WOTS parameters.
 * This is defined as a static inline function for efficiency.
 * @param params A pointer to the structure holding the runtime parameters (h, w, etc.).
 * @return The calculated size in bytes.
 */
static inline size_t xmss_eth_sig_size(const xmss_params *params) {
    /* layout: index(4) || wots_sig(wots_len * HASH_SIZE) || auth_path(h * HASH_SIZE) */
    return 4 + ((size_t)params->wots_len + (size_t)params->h) * HASH_SIZE;
}

/* Serialize XMSS signature to Ethereum compact form.*/
int xmss_eth_serialize(const xmss_params *params, const XMSSSignature *sig,
                       uint8_t *out, size_t out_cap,
                       size_t *out_len);

/* Deserialize XMSS signature (Ethereum compact form). */
int xmss_eth_deserialize(xmss_params *params, XMSSSignature *sig,
                         const uint8_t *in, size_t in_len);

/* Save/load Ethereum compact sig file. */
int xmss_eth_save_sig(const char *path, const XMSSSignature *sig, const xmss_params *params);
int xmss_eth_load_sig(const char *path, XMSSSignature *sig, xmss_params *params);

#endif