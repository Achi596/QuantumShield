#include "csprng.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <wincrypt.h>
static void os_random_bytes(uint8_t *buf, size_t len) {
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CSPRNG: CryptAcquireContext failed.\n");
        exit(1);
    }
    if (!CryptGenRandom(hProvider, (DWORD)len, buf)) {
        fprintf(stderr, "CSPRNG: CryptGenRandom failed.\n");
        exit(1);
    }
    CryptReleaseContext(hProvider, 0);
}
#else
#include <fcntl.h>
#include <unistd.h>
static void os_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open /dev/urandom"); exit(1); }
    ssize_t r = read(fd, buf, len);
    if (r < 0 || (size_t)r != len) { perror("read /dev/urandom"); exit(1); }
    close(fd);
}
#endif

// --- ChaCha20 core ---
#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))
#define QUARTERROUND(a,b,c,d) \
    a += b; d ^= a; d = ROTL32(d,16); \
    c += d; b ^= c; b = ROTL32(b,12); \
    a += b; d ^= a; d = ROTL32(d, 8); \
    c += d; b ^= c; b = ROTL32(b, 7);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    int i;
    for (i = 0; i < 16; i++) out[i] = in[i];
    for (i = 0; i < 10; i++) { // 20 rounds (2 per loop)
        QUARTERROUND(out[0], out[4], out[8],  out[12])
        QUARTERROUND(out[1], out[5], out[9],  out[13])
        QUARTERROUND(out[2], out[6], out[10], out[14])
        QUARTERROUND(out[3], out[7], out[11], out[15])
        QUARTERROUND(out[0], out[5], out[10], out[15])
        QUARTERROUND(out[1], out[6], out[11], out[12])
        QUARTERROUND(out[2], out[7], out[8],  out[13])
        QUARTERROUND(out[3], out[4], out[9],  out[14])
    }
    for (i = 0; i < 16; i++) out[i] += in[i];
}

static struct {
    uint32_t state[16];
    uint8_t buffer[64];
    int buffer_pos;
} csprng_ctx;

void csprng_init(const uint8_t *key, const uint8_t *nonce) {
    const uint8_t *constants = (const uint8_t*)"expand 32-byte k";
    memset(&csprng_ctx, 0, sizeof(csprng_ctx));

    csprng_ctx.state[0]  = ((uint32_t)constants[0])  | ((uint32_t)constants[1]<<8) |
                           ((uint32_t)constants[2]<<16) | ((uint32_t)constants[3]<<24);
    csprng_ctx.state[1]  = ((uint32_t)constants[4])  | ((uint32_t)constants[5]<<8) |
                           ((uint32_t)constants[6]<<16) | ((uint32_t)constants[7]<<24);
    csprng_ctx.state[2]  = ((uint32_t)constants[8])  | ((uint32_t)constants[9]<<8) |
                           ((uint32_t)constants[10]<<16) | ((uint32_t)constants[11]<<24);
    csprng_ctx.state[3]  = ((uint32_t)constants[12]) | ((uint32_t)constants[13]<<8) |
                           ((uint32_t)constants[14]<<16) | ((uint32_t)constants[15]<<24);

    uint8_t key_buf[32];
    uint8_t nonce_buf[12];

    if (key == NULL) os_random_bytes(key_buf, sizeof(key_buf)); else memcpy(key_buf, key, 32);
    if (nonce == NULL) os_random_bytes(nonce_buf, sizeof(nonce_buf)); else memcpy(nonce_buf, nonce, 12);

    for (int i = 0; i < 8; i++) {
        csprng_ctx.state[4 + i] =
            ((uint32_t)key_buf[i*4 + 0]) |
            ((uint32_t)key_buf[i*4 + 1] << 8) |
            ((uint32_t)key_buf[i*4 + 2] << 16) |
            ((uint32_t)key_buf[i*4 + 3] << 24);
    }

    csprng_ctx.state[12] = 0; // counter
    csprng_ctx.state[13] = ((uint32_t)nonce_buf[0])  |
                           ((uint32_t)nonce_buf[1]<<8) |
                           ((uint32_t)nonce_buf[2]<<16) |
                           ((uint32_t)nonce_buf[3]<<24);
    csprng_ctx.state[14] = ((uint32_t)nonce_buf[4])  |
                           ((uint32_t)nonce_buf[5]<<8) |
                           ((uint32_t)nonce_buf[6]<<16) |
                           ((uint32_t)nonce_buf[7]<<24);
    csprng_ctx.state[15] = ((uint32_t)nonce_buf[8])  |
                           ((uint32_t)nonce_buf[9]<<8) |
                           ((uint32_t)nonce_buf[10]<<16) |
                           ((uint32_t)nonce_buf[11]<<24);

    csprng_ctx.buffer_pos = 64;
}

static void refill_buffer() {
    uint32_t block[16];
    chacha20_block(block, csprng_ctx.state);
    for (int i = 0; i < 16; i++) {
        csprng_ctx.buffer[4*i + 0] = block[i] & 0xFF;
        csprng_ctx.buffer[4*i + 1] = (block[i] >> 8) & 0xFF;
        csprng_ctx.buffer[4*i + 2] = (block[i] >> 16) & 0xFF;
        csprng_ctx.buffer[4*i + 3] = (block[i] >> 24) & 0xFF;
    }
    csprng_ctx.state[12]++; // increment counter
    csprng_ctx.buffer_pos = 0;
}

void csprng_random_bytes(uint8_t *out, size_t len) {
    if (csprng_ctx.buffer_pos >= 64) refill_buffer();
    for (size_t i = 0; i < len; i++) {
        if (csprng_ctx.buffer_pos >= 64) refill_buffer();
        out[i] = csprng_ctx.buffer[csprng_ctx.buffer_pos++];
    }
}

void csprng_seed_from_int(uint64_t seed) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};

    // Expand seed into key and nonce (simple way: fill with repeated seed)
    for (int i = 0; i < 32; i += 8) {
        key[i + 0] = (seed >> 0) & 0xFF;
        key[i + 1] = (seed >> 8) & 0xFF;
        key[i + 2] = (seed >> 16) & 0xFF;
        key[i + 3] = (seed >> 24) & 0xFF;
        key[i + 4] = (seed >> 32) & 0xFF;
        key[i + 5] = (seed >> 40) & 0xFF;
        key[i + 6] = (seed >> 48) & 0xFF;
        key[i + 7] = (seed >> 56) & 0xFF;
    }

    for (int i = 0; i < 12; i++) {
        nonce[i] = (seed >> (i % 8) * 8) & 0xFF;
    }

    csprng_init(key, nonce);
}