// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Portions Copyright (c) 2018 The Monero developers
// Portions Copyright (c) 2018 The TurtleCoin Developers

#include "cryptonight.h"
#include "crypto/c_blake256.h"
#include "crypto/c_groestl.h"
#include "crypto/c_jh.h"
#include "crypto/c_keccak.h"
#include "crypto/c_skein.h"
#include "simd-utils.h"
#include <immintrin.h>
#include <stdio.h>

#ifndef __AES__
#include "soft_aes.h"
#endif

// Replacement macro for architectures without SSE4.2
#ifndef __SSE42__
#define _mm_extract_epi64(a, b)                                                \
  b == 1 ? _mm_cvtsi128_si64(_mm_castps_si128(                                 \
               _mm_movehl_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(a))))       \
         : _mm_cvtsi128_si64(a);
#endif // __SSE42__

extern __thread uint8_t *hp_state;

static void do_blake_hash(const void *input, size_t len, void *output) {
  blake256_hash((uint8_t *)output, input, len);
}

static void do_groestl_hash(const void *input, size_t len, void *output) {
  groestl(input, len * 8, (uint8_t *)output);
}

static void do_jh_hash(const void *input, size_t len, void *output) {
  int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t *)output);
  assert(SUCCESS == r);
}

static void do_skein_hash(const void *input, size_t len, void *output) {
  int r = c_skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t *)output);
  assert(SKEIN_SUCCESS == r);
}

static void (*const extra_hashes[4])(const void *, size_t, void *) = {
    do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1) {
  __m128i tmp4;
  tmp4 = _mm_slli_si128(tmp1, 0x04);
  tmp1 = _mm_xor_si128(tmp1, tmp4);
  tmp4 = _mm_slli_si128(tmp4, 0x04);
  tmp1 = _mm_xor_si128(tmp1, tmp4);
  tmp4 = _mm_slli_si128(tmp4, 0x04);
  tmp1 = _mm_xor_si128(tmp1, tmp4);
  return tmp1;
}

static inline void aes_genkey_sub(__m128i *xout0, __m128i *xout2,
                                  const uint8_t rcon) {
#ifdef __AES__
  __m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
#else
  __m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
#endif
  xout1 =
      _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
  *xout0 = sl_xor(*xout0);
  *xout0 = _mm_xor_si128(*xout0, xout1);
#ifdef __AES__
  xout1 = _mm_aeskeygenassist_si128(*xout0, 0x00);
#else
  xout1 = soft_aeskeygenassist(*xout0, 0x00);
#endif
  xout1 =
      _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
  *xout2 = sl_xor(*xout2);
  *xout2 = _mm_xor_si128(*xout2, xout1);
}

static inline void aes_genkey(const __m128i *memory, __m128i *k0, __m128i *k1,
                              __m128i *k2, __m128i *k3, __m128i *k4,
                              __m128i *k5, __m128i *k6, __m128i *k7,
                              __m128i *k8, __m128i *k9) {
  __m128i xout0 = _mm_load_si128(memory);
  __m128i xout2 = _mm_load_si128(memory + 1);
  *k0 = xout0;
  *k1 = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x01);
  *k2 = xout0;
  *k3 = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x02);
  *k4 = xout0;
  *k5 = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x04);
  *k6 = xout0;
  *k7 = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x08);
  *k8 = xout0;
  *k9 = xout2;
}

#ifdef __AES__
static __attribute__((always_inline)) void
aes_round(const __m128i *key, __m128i *x0, __m128i *x1, __m128i *x2,
          __m128i *x3, __m128i *x4, __m128i *x5, __m128i *x6, __m128i *x7) {
  *x0 = _mm_aesenc_si128(*x0, *key);
  *x1 = _mm_aesenc_si128(*x1, *key);
  *x2 = _mm_aesenc_si128(*x2, *key);
  *x3 = _mm_aesenc_si128(*x3, *key);
  *x4 = _mm_aesenc_si128(*x4, *key);
  *x5 = _mm_aesenc_si128(*x5, *key);
  *x6 = _mm_aesenc_si128(*x6, *key);
  *x7 = _mm_aesenc_si128(*x7, *key);
}
#else
static __attribute__((always_inline)) __m128i soft_aesenc(const __m128i *in,
                                                          const __m128i *key) {
  // saes_table is implemented in "soft_aes.h"
  const uint32_t x0 = ((const uint32_t *)(in))[0];
  const uint32_t x1 = ((const uint32_t *)(in))[1];
  const uint32_t x2 = ((const uint32_t *)(in))[2];
  const uint32_t x3 = ((const uint32_t *)(in))[3];

  const __m128i out = _mm_set_epi32(
      (saes_table[0][x3 & 0xff] ^ saes_table[1][(x0 >> 8) & 0xff] ^
       saes_table[2][(x1 >> 16) & 0xff] ^ saes_table[3][x2 >> 24]),
      (saes_table[0][x2 & 0xff] ^ saes_table[1][(x3 >> 8) & 0xff] ^
       saes_table[2][(x0 >> 16) & 0xff] ^ saes_table[3][x1 >> 24]),
      (saes_table[0][x1 & 0xff] ^ saes_table[1][(x2 >> 8) & 0xff] ^
       saes_table[2][(x3 >> 16) & 0xff] ^ saes_table[3][x0 >> 24]),
      (saes_table[0][x0 & 0xff] ^ saes_table[1][(x1 >> 8) & 0xff] ^
       saes_table[2][(x2 >> 16) & 0xff] ^ saes_table[3][x3 >> 24]));

  return _mm_xor_si128(out, *key);
}

static __attribute__((always_inline)) void
aes_round(const __m128i *key, __m128i *x0, __m128i *x1, __m128i *x2,
          __m128i *x3, __m128i *x4, __m128i *x5, __m128i *x6, __m128i *x7) {
  *x0 = soft_aesenc(x0, key);
  *x1 = soft_aesenc(x1, key);
  *x2 = soft_aesenc(x2, key);
  *x3 = soft_aesenc(x3, key);
  *x4 = soft_aesenc(x4, key);
  *x5 = soft_aesenc(x5, key);
  *x6 = soft_aesenc(x6, key);
  *x7 = soft_aesenc(x7, key);
}
#endif

// Size in L1 prefetch. 4KiB per thread.
#define PREFETCH_SIZE_B 4096
#define PREFETCH_SIZE PREFETCH_SIZE_B / 64
#define PREFETCH_TYPE_R _MM_HINT_T0
#define PREFETCH_TYPE_W _MM_HINT_ET0

static inline void explode_scratchpad(const __m128i *input, __m128i *output,
                                      const size_t memory) {
  __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
  __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

  aes_genkey(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xin0 = _mm_load_si128(input + 4);
  xin1 = _mm_load_si128(input + 5);
  xin2 = _mm_load_si128(input + 6);
  xin3 = _mm_load_si128(input + 7);
  xin4 = _mm_load_si128(input + 8);
  xin5 = _mm_load_si128(input + 9);
  xin6 = _mm_load_si128(input + 10);
  xin7 = _mm_load_si128(input + 11);

  size_t i;
  // Prefetch first X KiB of output into L1 cache.
  for (i = 0; i < PREFETCH_SIZE; i += 4) {
    _mm_prefetch(output + i, PREFETCH_TYPE_W);
  }

  for (i = 0; i < (memory / sizeof(__m128i)) - PREFETCH_SIZE; i += 8) {
    // Prefetch next 2 cache lines shifted X KiB in advance.
    _mm_prefetch(output + PREFETCH_SIZE, PREFETCH_TYPE_W);
    _mm_prefetch(output + PREFETCH_SIZE + 4, PREFETCH_TYPE_W);

    aes_round(&k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

    _mm_store_si128(output++, xin0);
    _mm_store_si128(output++, xin1);
    _mm_store_si128(output++, xin2);
    _mm_store_si128(output++, xin3);
    _mm_store_si128(output++, xin4);
    _mm_store_si128(output++, xin5);
    _mm_store_si128(output++, xin6);
    _mm_store_si128(output++, xin7);
  }

  // Last X KiB should be already prefetched.
  for (; i < memory / sizeof(__m128i); i += 8) {
    aes_round(&k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(&k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

    _mm_store_si128(output++, xin0);
    _mm_store_si128(output++, xin1);
    _mm_store_si128(output++, xin2);
    _mm_store_si128(output++, xin3);
    _mm_store_si128(output++, xin4);
    _mm_store_si128(output++, xin5);
    _mm_store_si128(output++, xin6);
    _mm_store_si128(output++, xin7);
  }
}

static inline void implode_scratchpad(const __m128i *input, __m128i *output,
                                      const size_t memory) {
  __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
  __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

  aes_genkey(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xout0 = _mm_load_si128(output + 4);
  xout1 = _mm_load_si128(output + 5);
  xout2 = _mm_load_si128(output + 6);
  xout3 = _mm_load_si128(output + 7);
  xout4 = _mm_load_si128(output + 8);
  xout5 = _mm_load_si128(output + 9);
  xout6 = _mm_load_si128(output + 10);
  xout7 = _mm_load_si128(output + 11);

  size_t i;
  // Prefetch first X KiB of input into L1 cache.
  for (i = 0; i < PREFETCH_SIZE; i += 4) {
    _mm_prefetch(input + i, PREFETCH_TYPE_R);
  }

  for (i = 0; i < (memory / sizeof(__m128i)) - PREFETCH_SIZE; i += 8) {
    // Prefetch next 2 cache lines shifted X KiB in advance.
    _mm_prefetch(input + PREFETCH_SIZE, PREFETCH_TYPE_R);
    _mm_prefetch(input + PREFETCH_SIZE + 4, PREFETCH_TYPE_R);

    xout0 = _mm_xor_si128(_mm_load_si128(input++), xout0);
    xout1 = _mm_xor_si128(_mm_load_si128(input++), xout1);
    xout2 = _mm_xor_si128(_mm_load_si128(input++), xout2);
    xout3 = _mm_xor_si128(_mm_load_si128(input++), xout3);
    xout4 = _mm_xor_si128(_mm_load_si128(input++), xout4);
    xout5 = _mm_xor_si128(_mm_load_si128(input++), xout5);
    xout6 = _mm_xor_si128(_mm_load_si128(input++), xout6);
    xout7 = _mm_xor_si128(_mm_load_si128(input++), xout7);

    aes_round(&k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
  }

  // Last X KiB should be already prefetched.
  for (; i < memory / sizeof(__m128i); i += 8) {
    xout0 = _mm_xor_si128(_mm_load_si128(input++), xout0);
    xout1 = _mm_xor_si128(_mm_load_si128(input++), xout1);
    xout2 = _mm_xor_si128(_mm_load_si128(input++), xout2);
    xout3 = _mm_xor_si128(_mm_load_si128(input++), xout3);
    xout4 = _mm_xor_si128(_mm_load_si128(input++), xout4);
    xout5 = _mm_xor_si128(_mm_load_si128(input++), xout5);
    xout6 = _mm_xor_si128(_mm_load_si128(input++), xout6);
    xout7 = _mm_xor_si128(_mm_load_si128(input++), xout7);

    aes_round(&k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
    aes_round(&k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6,
              &xout7);
  }

  _mm_store_si128(output + 4, xout0);
  _mm_store_si128(output + 5, xout1);
  _mm_store_si128(output + 6, xout2);
  _mm_store_si128(output + 7, xout3);
  _mm_store_si128(output + 8, xout4);
  _mm_store_si128(output + 9, xout5);
  _mm_store_si128(output + 10, xout6);
  _mm_store_si128(output + 11, xout7);
}

__attribute__((always_inline)) void
cryptonight_hash(const void *input, void *output, const uint32_t memory,
                 const uint32_t iterations, const uint32_t mask) {
  uint8_t state[200];

  keccak1600(input, 64, state);

  uint64_t *h0 = (uint64_t *)state;
  uint8_t *l0 = hp_state;

  explode_scratchpad((const __m128i *)state, (__m128i *)l0, memory);

  const uint64_t tweak1_2_0 =
      (*((uint64_t *)(&((uint8_t *)input)[35]))) ^ h0[24];

  uint64_t al0 = h0[0] ^ h0[4];
  uint64_t ah0 = h0[1] ^ h0[5];
  uint64_t idx0 = al0 & mask;

  __m128i bx0 =
      _mm_set_epi64x((int64_t)(h0[3] ^ h0[7]), (int64_t)(h0[2] ^ h0[6]));

  for (size_t i = 0; i < iterations; i++) {
    // AES
#ifdef __AES__
    const __m128i cx0 =
        _mm_aesenc_si128(_mm_load_si128((const __m128i *)(&l0[idx0])),
                         _mm_set_epi64x((int64_t)ah0, (int64_t)al0));
#else
    __m128i cx0 = _mm_load_si128((const __m128i *)(&l0[idx0]));
    const __m128i ax0 = _mm_set_epi64x((int64_t)ah0, (int64_t)al0);
    cx0 = soft_aesenc(&cx0, &ax0);
#endif

    // Post AES
    const __m128i tmp = _mm_xor_si128(bx0, cx0);
    ((uint64_t *)(&l0[idx0]))[0] = _mm_cvtsi128_si64(tmp);

    const uint64_t vh = _mm_extract_epi64(tmp, 1);

    const uint8_t x = (uint8_t)(vh >> 24);
    static const uint16_t table = 0x7531;
    const uint8_t index = (((x >> (3)) & 6) | (x & 1)) << 1;

    ((uint64_t *)(&l0[idx0]))[1] = vh ^ (((table >> index) & 0x3) << 28);

    const uint64_t cxl0 = (uint64_t)(_mm_cvtsi128_si64(cx0));
    idx0 = cxl0 & mask;

    register uint64_t hi, lo;
    const uint64_t cl = ((const uint64_t *)(&l0[idx0]))[0];
    const uint64_t ch = ((const uint64_t *)(&l0[idx0]))[1];

    __asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "1"(cxl0), "rm"(cl) : "cc");

    al0 += hi;
    ah0 += lo;

    ((uint64_t *)(&l0[idx0]))[0] = al0;
    ((uint64_t *)(&l0[idx0]))[1] = ah0 ^ tweak1_2_0;

    al0 ^= cl;
    ah0 ^= ch;
    idx0 = al0 & mask;

    bx0 = cx0;
  }

  implode_scratchpad((const __m128i *)l0, (__m128i *)state, memory);
  keccakf(h0, 24);
  extra_hashes[state[0] & 3](state, 200, output);
  memset(&((uint8_t *)output)[32], 0, 32);
}

// Variant      MEMORY            ITERATIONS      MASK
// Dark         512KiB, 2^19      2^17            (MEMORY - 16)
// Darklite     512KiB, 2^19      2^17            (MEMORY - 16) / 2
// Fast         2MiB,   2^21      2^18            (MEMORY - 16)
// Lite         1Mib,   2^20      2^18            (MEMORY - 16)
// Turtle       256KiB, 2^18      2^16            (MEMORY - 16)
// Turtlelite   256KiB, 2^18      2^16            (MEMORY - 16) / 2
void cryptonight_dark_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 524288, 131072, 524272);
}

void cryptonight_darklite_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 524288, 131072, 262128);
}

void cryptonight_fast_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 2097152, 262144, 2097136);
}

void cryptonight_lite_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 1048576, 262144, 1048560);
}

void cryptonight_turtle_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 262144, 65536, 262128);
}

void cryptonight_turtlelite_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 262144, 65536, 131056);
}

#ifdef __AVX2__ // GR_4WAY

// Requires 2x memory allocated in hp_state.
__attribute__((always_inline)) void
cryptonight_2way_hash(const void *input0, const void *input1, void *output0,
                      void *output1, const uint32_t memory,
                      const uint32_t iterations, const uint32_t mask) {
  uint8_t state0[200];
  uint8_t state1[200];

  keccak1600(input0, 64, state0);
  keccak1600(input1, 64, state1);

  uint64_t *h0 = (uint64_t *)state0;
  uint64_t *h1 = (uint64_t *)state1;
  uint8_t *l0 = hp_state;
  uint8_t *l1 = hp_state + memory;

  explode_scratchpad((const __m128i *)state0, (__m128i *)l0, memory);
  explode_scratchpad((const __m128i *)state1, (__m128i *)l1, memory);

  const uint64_t tweak1_2_0 =
      (*((uint64_t *)(&((uint8_t *)input0)[35]))) ^ h0[24];
  const uint64_t tweak1_2_1 =
      (*((uint64_t *)(&((uint8_t *)input1)[35]))) ^ h1[24];

  uint64_t al0 = h0[0] ^ h0[4];
  uint64_t ah0 = h0[1] ^ h0[5];
  uint64_t al1 = h1[0] ^ h1[4];
  uint64_t ah1 = h1[1] ^ h1[5];
  uint64_t idx0 = al0 & mask;
  uint64_t idx1 = al1 & mask;

  __m128i bx0 =
      _mm_set_epi64x((int64_t)(h0[3] ^ h0[7]), (int64_t)(h0[2] ^ h0[6]));
  __m128i bx1 =
      _mm_set_epi64x((int64_t)(h1[3] ^ h1[7]), (int64_t)(h1[2] ^ h1[6]));

  for (size_t i = 0; i < iterations; i++) {
    // AES 1
    const __m128i cx0 =
        _mm_aesenc_si128(_mm_load_si128((const __m128i *)(&l0[idx0])),
                         _mm_set_epi64x((int64_t)ah0, (int64_t)al0));
    const uint64_t cxl0 = (uint64_t)(_mm_cvtsi128_si64(cx0));
    _mm_prefetch(&l0[cxl0 & mask], _MM_HINT_ET0);

    const __m128i cx1 =
        _mm_aesenc_si128(_mm_load_si128((const __m128i *)(&l1[idx1])),
                         _mm_set_epi64x((int64_t)ah1, (int64_t)al1));
    const uint64_t cxl1 = (uint64_t)(_mm_cvtsi128_si64(cx1));
    _mm_prefetch(&l1[cxl1 & mask], _MM_HINT_ET0);

    // Post AES
    const __m128i tmp0 = _mm_xor_si128(bx0, cx0);
    ((uint64_t *)(&l0[idx0]))[0] = _mm_cvtsi128_si64(tmp0);
    const uint64_t vh0 = _mm_extract_epi64(tmp0, 1);
    const uint8_t x0 = (uint8_t)(vh0 >> 24);
    static const uint16_t table = 0x7531;
    const uint8_t index0 = (((x0 >> (3)) & 6) | (x0 & 1)) << 1;
    ((uint64_t *)(&l0[idx0]))[1] = vh0 ^ (((table >> index0) & 0x3) << 28);

    const __m128i tmp1 = _mm_xor_si128(bx1, cx1);
    ((uint64_t *)(&l1[idx1]))[0] = _mm_cvtsi128_si64(tmp1);
    const uint64_t vh1 = _mm_extract_epi64(tmp1, 1);
    const uint8_t x1 = (uint8_t)(vh1 >> 24);
    const uint8_t index1 = (((x1 >> (3)) & 6) | (x1 & 1)) << 1;
    ((uint64_t *)(&l1[idx1]))[1] = vh1 ^ (((table >> index1) & 0x3) << 28);

    idx0 = cxl0 & mask;
    idx1 = cxl1 & mask;

    register uint64_t hi, lo;
    const uint64_t cl0 = ((const uint64_t *)(&l0[idx0]))[0];
    const uint64_t ch0 = ((const uint64_t *)(&l0[idx0]))[1];

    __asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "1"(cxl0), "rm"(cl0) : "cc");

    al0 += hi;
    ah0 += lo;

    ((uint64_t *)(&l0[idx0]))[0] = al0;
    ((uint64_t *)(&l0[idx0]))[1] = ah0 ^ tweak1_2_0;

    al0 ^= cl0;
    idx0 = al0 & mask;
    _mm_prefetch(&l0[idx0], _MM_HINT_ET0);

    ah0 ^= ch0;

    const uint64_t cl1 = ((const uint64_t *)(&l1[idx1]))[0];
    const uint64_t ch1 = ((const uint64_t *)(&l1[idx1]))[1];

    __asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "1"(cxl1), "rm"(cl1) : "cc");

    al1 += hi;
    ah1 += lo;

    ((uint64_t *)(&l1[idx1]))[0] = al1;
    ((uint64_t *)(&l1[idx1]))[1] = ah1 ^ tweak1_2_1;

    al1 ^= cl1;
    idx1 = al1 & mask;
    _mm_prefetch(&l1[idx1], _MM_HINT_ET0);

    ah1 ^= ch1;

    bx0 = cx0;
    bx1 = cx1;
  }

  implode_scratchpad((const __m128i *)l0, (__m128i *)state0, memory);
  keccakf(h0, 24);
  extra_hashes[state0[0] & 3](state0, 200, output0);
  memset(&((uint8_t *)output0)[32], 0, 32);

  implode_scratchpad((const __m128i *)l1, (__m128i *)state1, memory);
  keccakf(h1, 24);
  extra_hashes[state1[0] & 3](state1, 200, output1);
  memset(&((uint8_t *)output1)[32], 0, 32);
}

// Variant      MEMORY            ITERATIONS      CN_AES_INIT
// Dark         512KiB, 2^19      2^17            (MEMORY - 16)
// Darklite     512KiB, 2^19      2^17            (MEMORY - 16) / 2
// Fast         2MiB,   2^21      2^18            (MEMORY - 16)
// Lite         1Mib,   2^20      2^18            (MEMORY - 16)
// Turtle       256KiB, 2^18      2^16            (MEMORY - 16)
// Turtlelite   256KiB, 2^18      2^16            (MEMORY - 16) / 2
void cryptonight_dark_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 524288, 131072,
                        524272);
}

void cryptonight_darklite_2way_hash(const void *input0, const void *input1,
                                    void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 524288, 131072,
                        262128);
}

void cryptonight_fast_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 2097152, 262144,
                        2097136);
}

void cryptonight_lite_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 1048576, 262144,
                        1048560);
}

void cryptonight_turtle_2way_hash(const void *input0, const void *input1,
                                  void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 262144, 65536,
                        262128);
}

void cryptonight_turtlelite_2way_hash(const void *input0, const void *input1,
                                      void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 262144, 65536,
                        131056);
}

#endif // __AVX2__ / 2way
