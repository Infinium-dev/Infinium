// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto/cryptonight-variants.h"

#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

#if !TARGET_OS_IPHONE // We need "if x86", but no portable way to express that

#include <emmintrin.h>
#include <wmmintrin.h>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

//#include "crypto/oaes/aesb.h"
//tiny aesb
#if defined(__cplusplus)
extern "C"
{
#endif

#define TABLE_ALIGN 32
#define WPOLY 0x011b
#define N_COLS 4
#define AES_BLOCK_SIZE 16
#define RC_LENGTH (5 * (AES_BLOCK_SIZE / 4 - 2))

#if defined(_MSC_VER)
#define aesb_ALIGN __declspec(align(TABLE_ALIGN))
#elif defined(__GNUC__)
#define aesb_ALIGN __attribute__((aligned(16)))
#else
#define aesb_ALIGN
#endif

#define rf1(r, c) (r)
#define word_in(x, c) (*((uint32_t *)(x) + (c)))
#define word_out(x, c, v) (*((uint32_t *)(x) + (c)) = (v))

#define s(x, c) x[c]
#define si(y, x, c) (s(y, c) = word_in(x, c))
#define so(y, x, c) word_out(y, c, s(x, c))
#define state_in(y, x) \
    si(y, x, 0);       \
    si(y, x, 1);       \
    si(y, x, 2);       \
    si(y, x, 3)
#define state_out(y, x) \
    so(y, x, 0);        \
    so(y, x, 1);        \
    so(y, x, 2);        \
    so(y, x, 3)
#define round(rm, y, x, k) \
    rm(y, x, k, 0);        \
    rm(y, x, k, 1);        \
    rm(y, x, k, 2);        \
    rm(y, x, k, 3)
#define to_byte(x) ((x)&0xff)
#define bval(x, n) to_byte((x) >> (8 * (n)))

#define fwd_var(x, r, c)                                                                           \
    (r == 0 ? (c == 0 ? s(x, 0) : c == 1 ? s(x, 1) : c == 2 ? s(x, 2) : s(x, 3))                   \
            : r == 1 ? (c == 0 ? s(x, 1) : c == 1 ? s(x, 2) : c == 2 ? s(x, 3) : s(x, 0))          \
                     : r == 2 ? (c == 0 ? s(x, 2) : c == 1 ? s(x, 3) : c == 2 ? s(x, 0) : s(x, 1)) \
                              : (c == 0 ? s(x, 3) : c == 1 ? s(x, 0) : c == 2 ? s(x, 1) : s(x, 2)))

#define fwd_rnd(y, x, k, c) (s(y, c) = (k)[c] ^ four_tables(x, t_use(f, n), fwd_var, rf1, c))

#define sb_data(w)                                                                  \
    {                                                                               \
        w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),     \
            w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76), \
            w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0), \
            w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0), \
            w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc), \
            w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15), \
            w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a), \
            w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75), \
            w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0), \
            w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84), \
            w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b), \
            w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf), \
            w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85), \
            w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8), \
            w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5), \
            w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2), \
            w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17), \
            w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73), \
            w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88), \
            w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb), \
            w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c), \
            w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79), \
            w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9), \
            w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08), \
            w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6), \
            w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a), \
            w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e), \
            w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e), \
            w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94), \
            w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf), \
            w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68), \
            w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16)  \
    }

#define rc_data(w)                                                              \
    {                                                                           \
        w(0x01), w(0x02), w(0x04), w(0x08), w(0x10), w(0x20), w(0x40), w(0x80), \
            w(0x1b), w(0x36)                                                    \
    }

#define bytes2word(b0, b1, b2, b3) (((uint32_t)(b3) << 24) | \
                                    ((uint32_t)(b2) << 16) | ((uint32_t)(b1) << 8) | (b0))

#define h0(x) (x)
#define w0(p) bytes2word(p, 0, 0, 0)
#define w1(p) bytes2word(0, p, 0, 0)
#define w2(p) bytes2word(0, 0, p, 0)
#define w3(p) bytes2word(0, 0, 0, p)

#define u0(p) bytes2word(f2(p), p, p, f3(p))
#define u1(p) bytes2word(f3(p), f2(p), p, p)
#define u2(p) bytes2word(p, f3(p), f2(p), p)
#define u3(p) bytes2word(p, p, f3(p), f2(p))

#define v0(p) bytes2word(fe(p), f9(p), fd(p), fb(p))
#define v1(p) bytes2word(fb(p), fe(p), f9(p), fd(p))
#define v2(p) bytes2word(fd(p), fb(p), fe(p), f9(p))
#define v3(p) bytes2word(f9(p), fd(p), fb(p), fe(p))

#define f2(x) ((x << 1) ^ (((x >> 7) & 1) * WPOLY))
#define f4(x) ((x << 2) ^ (((x >> 6) & 1) * WPOLY) ^ (((x >> 6) & 2) * WPOLY))
#define f8(x) ((x << 3) ^ (((x >> 5) & 1) * WPOLY) ^ (((x >> 5) & 2) * WPOLY) ^ (((x >> 5) & 4) * WPOLY))
#define f3(x) (f2(x) ^ x)
#define f9(x) (f8(x) ^ x)
#define fb(x) (f8(x) ^ f2(x) ^ x)
#define fd(x) (f8(x) ^ f4(x) ^ x)
#define fe(x) (f8(x) ^ f4(x) ^ f2(x))

#define t_dec(m, n) t_##m##n
#define t_set(m, n) t_##m##n
#define t_use(m, n) t_##e##n

#define d_4(t, n, b, e, f, g, h) aesb_ALIGN const t n[4][256] = {b(e), b(f), b(g), b(h)}

#define four_tables(x, tab, vf, rf, c) \
    (tab[0][bval(vf(x, 0, c), rf(0, c))] ^ tab[1][bval(vf(x, 1, c), rf(1, c))] ^ tab[2][bval(vf(x, 2, c), rf(2, c))] ^ tab[3][bval(vf(x, 3, c), rf(3, c))])

    d_4(uint32_t, t_dec(e, n), sb_data, u0, u1, u2, u3);

    void aesb_single_round2(const uint8_t *in, uint8_t *out, uint8_t *expandedKey)
    {
        uint32_t b0[4], b1[4];
        const uint32_t *kp = (uint32_t *)expandedKey;
        state_in(b0, in);

        round(fwd_rnd, b1, b0, kp);

        state_out(out, b1);
    }

    void aesb_pseudo_round2(const uint8_t *in, uint8_t *out, uint8_t *expandedKey)
    {
        uint32_t b0[4], b1[4];
        const uint32_t *kp = (uint32_t *)expandedKey;
        state_in(b0, in);

        round(fwd_rnd, b1, b0, kp);
        round(fwd_rnd, b0, b1, kp + 1 * N_COLS);
        round(fwd_rnd, b1, b0, kp + 2 * N_COLS);
        round(fwd_rnd, b0, b1, kp + 3 * N_COLS);
        round(fwd_rnd, b1, b0, kp + 4 * N_COLS);
        round(fwd_rnd, b0, b1, kp + 5 * N_COLS);
        round(fwd_rnd, b1, b0, kp + 6 * N_COLS);
        round(fwd_rnd, b0, b1, kp + 7 * N_COLS);
        round(fwd_rnd, b1, b0, kp + 8 * N_COLS);
        round(fwd_rnd, b0, b1, kp + 9 * N_COLS);

        state_out(out, b0);
    }

#if defined(__cplusplus)
}
#endif
//tyny aesb
#include "initializer.h"
#include "int-util.h"
#include "crypto/hash-impl.h"
#include "crypto/oaes/oaes_lib.h"

#if defined(__GNUC__)
#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))
#else
#define likely(x) (x)
#define unlikely(x) (x)
#define __attribute__(x)
#endif

#if defined(_MSC_VER)
#define restrict
#endif

#define MEMORY (1 << 21) /* 2 MiB */
#define ITER (1 << 19)
#define MASK 0x1FFFF0

// Cryptonight Lite
#define LITE_MEMORY (1 << 20) /* 1 MiB */
#define LITE_ITER (1 << 18)
#define LITE_MASK 0xFFFF0

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32 /*16*/
#define INIT_SIZE_BLK 8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE) // 128

#pragma pack(push, 1)
union cn_slow_hash_state
{
    union hash_state hs;
    struct
    {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};
#pragma pack(pop)

#if defined(_MSC_VER)
#define ALIGNED_DATA(x) __declspec(align(x))
#define ALIGNED_DECL(t, x) ALIGNED_DATA(x) \
t
#elif defined(__GNUC__)
#define ALIGNED_DATA(x) __attribute__((aligned(x)))
#define ALIGNED_DECL(t, x) t ALIGNED_DATA(x)
#endif

struct cn_ctx
{
    ALIGNED_DECL(uint8_t long_state[MEMORY], 16);
    ALIGNED_DECL(union cn_slow_hash_state state, 16);
    ALIGNED_DECL(uint8_t text[INIT_SIZE_BYTE], 16);
    ALIGNED_DECL(uint64_t a[AES_BLOCK_SIZE >> 3], 16);
    ALIGNED_DECL(uint64_t b[AES_BLOCK_SIZE >> 3], 16);
    ALIGNED_DECL(uint8_t c[AES_BLOCK_SIZE], 16);
    oaes_ctx *aes_ctx;
};

static_assert(sizeof(struct cn_ctx) == SLOW_HASH_CONTEXT_SIZE, "Invalid structure size");

static void ExpandAESKey256_sub1(__m128i *tmp1, __m128i *tmp2)
{
    __m128i tmp4;
    *tmp2 = _mm_shuffle_epi32(*tmp2, 0xFF);
    tmp4 = _mm_slli_si128(*tmp1, 0x04);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);
    *tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static void ExpandAESKey256_sub2(__m128i *tmp1, __m128i *tmp3)
{
    __m128i tmp2, tmp4;

    tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x00);
    tmp2 = _mm_shuffle_epi32(tmp4, 0xAA);
    tmp4 = _mm_slli_si128(*tmp3, 0x04);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);
    *tmp3 = _mm_xor_si128(*tmp3, tmp2);
}

// Special thanks to Intel for helping me
// with ExpandAESKey256() and its subroutines
static void ExpandAESKey256(uint8_t *keybuf)
{
    __m128i tmp1, tmp2, tmp3, *keys;

    keys = (__m128i *)keybuf;

    tmp1 = _mm_load_si128((__m128i *)keybuf);
    tmp3 = _mm_load_si128((__m128i *)(keybuf + 0x10));

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[2] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[3] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[4] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[5] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[6] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[7] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[8] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[9] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[10] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[11] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[12] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[13] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[14] = tmp1;
}

static void (*const extra_hashes[4])(const void *, size_t, unsigned char *) =
    {
        hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein};

#include "crypto/slow-hash_x86.inl"
#define AESNI
#include "crypto/slow-hash_x86.inl"

static int cpu_has_aesni(void)
{
    int ecx;
#if defined(_MSC_VER)
    int cpuinfo[4];
    __cpuid(cpuinfo, 1);
    ecx = cpuinfo[2];
#else
    int a, b, d;
    __cpuid(1, a, b, ecx, d);
#endif
    return (ecx & (1 << 25)) ? 1 : 0;
}

static void cn_slow_hash_runtime_aes_check(void *a, const void *b, size_t c, void *d, int lite, int variant)
{
    if (cpu_has_aesni())
        cn_slow_hash_aesni(a, b, c, d, lite, variant);
    else
        cn_slow_hash_noaesni(a, b, c, d, lite, variant);
}

static void (*cn_slow_hash_fp)(void *, const void *, size_t, void *, int lite, int variant) = cn_slow_hash_runtime_aes_check;

void cn_slow_hash_lite_v1(void *a, const void *b, size_t c, void *d, int lite, int variant)
{
    (*cn_slow_hash_fp)(a, b, c, d, lite, variant);
}

// If INITIALIZER fails to compile on your platform, just comment out 3 lines below
INITIALIZER(detect_aes)
{
    cn_slow_hash_fp = cpu_has_aesni() ? &cn_slow_hash_aesni : &cn_slow_hash_noaesni;
}

#endif // !TARGET_OS_IPHONE