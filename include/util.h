#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

// Securely zeroes memory to prevent sensitive data leakage.
void secure_zero_memory(void *ptr, size_t len);

// Conditionally selects bytes from two arrays based on a mask in constant time.
void conditional_select(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint32_t mask, size_t len);

#endif