#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "xmss.h"

int main() {
    XMSSKey key;
    XMSSSignature sig;

    // Simple fixed message
    uint8_t msg[HASH_SIZE] = "XMSS demo message for signing";

    // Generate keys
    printf("Generating XMSS keypair...\n");
    xmss_keygen(&key);

    // Pick index = 0 for this demo
    int index = 0;
    xmss_sign(msg, &key, &sig, index);

    printf("\nSignature generated for index %d.\n", index);
    printf("Public Root Hash: ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%02X", key.root[i]);
    printf("\n");

    // Verification
    int result = xmss_verify(msg, &sig, key.root);
    if (result)
        printf("✅ Signature verification succeeded.\n");
    else
        printf("❌ Signature verification failed.\n");

    return result ? 0 : 1;
}
