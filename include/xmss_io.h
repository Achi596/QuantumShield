#ifndef XMSS_IO_H
#define XMSS_IO_H

#include <stdint.h>
#include "xmss.h"
#include "wots.h"

/* --- File format constants --- */
#define XMSS_IO_MAGIC_KEY  0x584D5353u  /* 'XMSS' */
#define XMSS_IO_MAGIC_SIG  0x584D5347u  /* 'XMSG' */
#define XMSS_IO_VERSION    1

/* Hash identifiers */
#define XMSS_IO_HASH_SHAKE256 1

/* Save/load XMSS private key (with header).
 * Returns 0 on success, <0 on error, 0 on load if file missing (like fopen fail).
 */
int xmss_io_save_key(const char *path, const XMSSKey *key,
                     uint8_t hash_id);
int xmss_io_load_key(const char *path, XMSSKey *key,
                     uint8_t *hash_id_out);

/* Save/load XMSS signature (with header).
 * Returns 0/1 semantics like above.
 */
int xmss_io_save_sig(const char *path, const XMSSSignature *sig,
                     uint8_t hash_id);
int xmss_io_load_sig(const char *path, XMSSSignature *sig,
                     uint8_t *hash_id_out);

#endif
