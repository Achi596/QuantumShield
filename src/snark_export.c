#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>  // Ensure you link with -ljansson

#include "snark_export.h"
#include "xmss.h"
#include "wots.h"
#include "hash.h"

extern XMSSKey global_xmss_key;
extern XMSSSignature global_last_signature;
extern uint8_t global_last_root[HASH_SIZE];
extern uint32_t global_last_index;

/* Export SNARK data to JSON format */
int export_snark_json(const char *filename, const uint8_t *msg, size_t msg_len, int h, int w) {
    json_t *root = json_object();

    // Add message
    size_t hex_len = msg_len * 2 + 1;
    char *hex_buf = malloc(hex_len);
    for (size_t i = 0; i < msg_len; i++)
        sprintf(&hex_buf[i * 2], "%02X", msg[i]);
    json_object_set_new(root, "message", json_string(hex_buf));
    free(hex_buf);

    // Add root
    char root_hex[HASH_SIZE * 2 + 1];
    for (int i = 0; i < HASH_SIZE; i++)
        sprintf(&root_hex[i * 2], "%02X", global_last_root[i]);
    json_object_set_new(root, "root", json_string(root_hex));

    // Add index
    json_object_set_new(root, "index", json_integer(global_last_index));

    // Add signature
    json_t *sig_arr = json_array();
    // for (int i = 0; i < w; i++) {
    //     char buf[HASH_SIZE * 2 + 1];
    //     for (int j = 0; j < HASH_SIZE; j++)
    //         sprintf(&buf[j * 2], "%02X", global_last_signature.wots_sig.sig[i][j]);
    //     json_array_append_new(sig_arr, json_string(buf));
    // }

    // Add auth path
    json_t *auth_arr = json_array();
    for (int i = 0; i < h; i++) {
        char buf[HASH_SIZE * 2 + 1];
        for (int j = 0; j < HASH_SIZE; j++)
            sprintf(&buf[j * 2], "%02X", global_last_signature.auth_path[i][j]);
        json_array_append_new(auth_arr, json_string(buf));
    }

    // Add WOTS signature and auth path to root JSON
    json_object_set_new(root, "wots_signature", sig_arr);
    json_object_set_new(root, "auth_path", auth_arr);

    // Write JSON to file    
    if (json_dump_file(root, filename, JSON_INDENT(2)) != 0) {
        json_decref(root);
        return -1;
    }

    // Clean up
    json_decref(root);
    return 0;
}
