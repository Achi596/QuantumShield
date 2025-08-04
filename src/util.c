#include "util.h"
#include <string.h>
void secure_zero_memory(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
        }
}
void conditional_select(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint32_t mask, size_t len) {
for (size_t i = 0; i < len; i++) {
    dst[i] = (mask & a[i]) | (~mask & b[i]);
    }
}