#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Securely erases a region of memory.
 * Uses a volatile pointer to prevent the compiler from optimizing the call away.
 * @param ptr Pointer to the memory to erase.
 * @param len Number of bytes to erase.
 */
void secure_zero_memory(void *ptr, size_t len);

/**
 * @brief Constant-time conditional select.
 * If mask is all 1s, copies 'a' to 'dst'. If mask is all 0s, copies 'b' to 'dst'.
 * The mask should be generated from a condition like: uint32_t mask = (cond) ? -1 : 0;
 * @param dst Output buffer.
 * @param a Value if condition is true.
 * @param b Value if condition is false.
 * @param mask The conditional mask.
 * @param len The length of the buffers.
 */
void conditional_select(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint32_t mask, size_t len);

#endif