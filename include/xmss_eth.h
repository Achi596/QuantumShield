#ifndef XMSS_ETH_H
#define XMSS_ETH_H

#include <stddef.h>
#include <stdint.h>
#include "xmss.h"
#include "wots.h"

/* Max allowed serialized signature size for Ethereum transaction data payloads. */
#define XMSS_ETH_SIG_MAX_BYTES 4096

/* Compute the serialized size for current build params. */
static inline size_t xmss_eth_sig_size(void) {
    /* layout: index(4) || wots_sig(WOTS_LEN*N) || auth_path(h*N) */
    return 4 + ((size_t)WOTS_LEN + (size_t)XMSS_TREE_HEIGHT) * HASH_SIZE;
}

/* Serialize XMSS signature to Ethereum compact form.*/
int xmss_eth_serialize(const XMSSSignature *sig,
                       uint8_t *out, size_t out_cap,
                       size_t *out_len);

/* Deserialize XMSS signature (Ethereum compact form). */
int xmss_eth_deserialize(XMSSSignature *sig,
                         const uint8_t *in, size_t in_len);

/* Save/load Ethereum compact sig file. */
int xmss_eth_save_sig(const char *path, const XMSSSignature *sig);
int xmss_eth_load_sig(const char *path, XMSSSignature *sig, size_t *sig_len_out);

#endif
