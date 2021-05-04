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

static __attribute__((always_inline)) uint64_t
__umul128(const uint64_t *a, const uint64_t *b, uint64_t *hi) {
  unsigned __int128 r = (unsigned __int128)(*a) * (unsigned __int128)(*b);
  *hi = r >> 64;
  return (uint64_t)r;
}

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

  for (size_t i = 0; i < memory / sizeof(__m128i); i += 8) {
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

    _mm_store_si128(output + 0, xin0);
    _mm_store_si128(output + 1, xin1);
    _mm_store_si128(output + 2, xin2);
    _mm_store_si128(output + 3, xin3);

    _mm_store_si128(output + 4, xin4);
    _mm_store_si128(output + 5, xin5);
    _mm_store_si128(output + 6, xin6);
    _mm_store_si128(output + 7, xin7);

    output += 8;
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

  for (size_t i = 0; i < memory / sizeof(__m128i);) {
    xout0 = _mm_xor_si128(_mm_load_si128(input + 0), xout0);
    xout1 = _mm_xor_si128(_mm_load_si128(input + 1), xout1);
    xout2 = _mm_xor_si128(_mm_load_si128(input + 2), xout2);
    xout3 = _mm_xor_si128(_mm_load_si128(input + 3), xout3);
    xout4 = _mm_xor_si128(_mm_load_si128(input + 4), xout4);
    xout5 = _mm_xor_si128(_mm_load_si128(input + 5), xout5);
    xout6 = _mm_xor_si128(_mm_load_si128(input + 6), xout6);
    xout7 = _mm_xor_si128(_mm_load_si128(input + 7), xout7);

    input += 8;
    i += 8;

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

  const uint64_t tweak1_2_0 = (*((uint64_t *)(input + 35))) ^ h0[24];

  uint64_t al0 = h0[0] ^ h0[4];
  uint64_t ah0 = h0[1] ^ h0[5];
  uint64_t idx0 = al0 & mask;
  __m128i bx0 =
      _mm_set_epi64x((int64_t)(h0[3] ^ h0[7]), (int64_t)(h0[2] ^ h0[6]));

  for (size_t i = 0; i < iterations; i++) {
    // Pre AES
    __m128i cx = _mm_load_si128((const __m128i *)(&l0[idx0]));

    // AES
#ifdef __AES__
    cx = _mm_aesenc_si128(cx, _mm_set_epi64x((int64_t)(ah0), (int64_t)(al0)));
#else
    const __m128i ax0 = _mm_set_epi64x((int64_t)(ah0), (int64_t)(al0));
    cx = soft_aesenc(&cx, &ax0);
    // cx = soft_aesenc(&cx, &ax0);
#endif

    // Post AES
    __m128i tmp = _mm_xor_si128(bx0, cx);
    ((uint64_t *)(&l0[idx0]))[0] = _mm_cvtsi128_si64(tmp);

    tmp = _mm_castps_si128(
        _mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
    uint64_t vh = _mm_cvtsi128_si64(tmp);

    const uint8_t x = (uint8_t)(vh >> 24);
    static const uint16_t table = 0x7531;
    const uint8_t index = (((x >> (3)) & 6) | (x & 1)) << 1;
    vh ^= ((table >> index) & 0x3) << 28;

    ((uint64_t *)(&l0[idx0]))[1] = vh;

    const uint64_t cx0l = (uint64_t)(_mm_cvtsi128_si64(cx));
    idx0 = cx0l & mask;

    uint64_t hi, lo, cl, ch;
    cl = ((uint64_t *)(&l0[idx0]))[0];
    ch = ((uint64_t *)(&l0[idx0]))[1];

    lo = __umul128(&cx0l, &cl, &hi);
    //__asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "1"(cx0l), "rm"(cl) : "cc");

    al0 += hi;
    ah0 += lo;

    ((uint64_t *)(&l0[idx0]))[0] = al0;
    ((uint64_t *)(&l0[idx0]))[1] = ah0 ^ tweak1_2_0;

    al0 ^= cl;
    ah0 ^= ch;

    idx0 = al0 & mask;
    bx0 = cx;
  }

  implode_scratchpad((const __m128i *)l0, (__m128i *)state, memory);
  keccakf(h0, 24);
  extra_hashes[state[0] & 3](state, 200, output);
  memset(output + 32, 0, 32);
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

#define RDATA_ALIGN16 __attribute__((aligned(16)))
#define R128(x) ((__m128i *)(x))

#define NONCE_POINTER(input) (((const void *)input) + 35)
#define state_index(x, cn_aes_init) (((((uint64_t)x) >> 4) & cn_aes_init) << 4)

static inline void aes_pseudo_round(const void *in, void *out,
                                    const void *expandedKey, int nblocks) {
  __m128i *k = R128(expandedKey);
  __m128i d;
  int i;

  for (i = 0; i < nblocks; i++) {
    d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
    d = _mm_aesenc_si128(d, *R128(&k[0]));
    d = _mm_aesenc_si128(d, *R128(&k[1]));
    d = _mm_aesenc_si128(d, *R128(&k[2]));
    d = _mm_aesenc_si128(d, *R128(&k[3]));
    d = _mm_aesenc_si128(d, *R128(&k[4]));
    d = _mm_aesenc_si128(d, *R128(&k[5]));
    d = _mm_aesenc_si128(d, *R128(&k[6]));
    d = _mm_aesenc_si128(d, *R128(&k[7]));
    d = _mm_aesenc_si128(d, *R128(&k[8]));
    d = _mm_aesenc_si128(d, *R128(&k[9]));
    _mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
  }
}

static inline void aes_pseudo_round_xor(const void *in, void *out,
                                        const void *expandedKey,
                                        const void * xor, int nblocks) {
  __m128i *k = R128(expandedKey);
  __m128i *x = R128(xor);
  __m128i d;
  int i;

  for (i = 0; i < nblocks; i++) {
    d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
    d = _mm_xor_si128(d, *R128(x++));
    d = _mm_aesenc_si128(d, *R128(&k[0]));
    d = _mm_aesenc_si128(d, *R128(&k[1]));
    d = _mm_aesenc_si128(d, *R128(&k[2]));
    d = _mm_aesenc_si128(d, *R128(&k[3]));
    d = _mm_aesenc_si128(d, *R128(&k[4]));
    d = _mm_aesenc_si128(d, *R128(&k[5]));
    d = _mm_aesenc_si128(d, *R128(&k[6]));
    d = _mm_aesenc_si128(d, *R128(&k[7]));
    d = _mm_aesenc_si128(d, *R128(&k[8]));
    d = _mm_aesenc_si128(d, *R128(&k[9]));
    _mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
  }
}

static inline void aes_256_assist1(__m128i *t1, __m128i *t2) {
  __m128i t4;
  *t2 = _mm_shuffle_epi32(*t2, 0xff);
  t4 = _mm_slli_si128(*t1, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  *t1 = _mm_xor_si128(*t1, *t2);
}

static inline void aes_256_assist2(__m128i *t1, __m128i *t3) {
  __m128i t2, t4;
  t4 = _mm_aeskeygenassist_si128(*t1, 0x00);
  t2 = _mm_shuffle_epi32(t4, 0xaa);
  t4 = _mm_slli_si128(*t3, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  *t3 = _mm_xor_si128(*t3, t2);
}

static inline void aes_expand_key(const void *key, void *expandedKey) {
  __m128i *ek = R128(expandedKey);
  __m128i t1, t2, t3;

  t1 = _mm_loadu_si128(R128(key));
  t3 = _mm_loadu_si128(R128(key + 16));

  ek[0] = t1;
  ek[1] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x01);
  aes_256_assist1(&t1, &t2);
  ek[2] = t1;
  aes_256_assist2(&t1, &t3);
  ek[3] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x02);
  aes_256_assist1(&t1, &t2);
  ek[4] = t1;
  aes_256_assist2(&t1, &t3);
  ek[5] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x04);
  aes_256_assist1(&t1, &t2);
  ek[6] = t1;
  aes_256_assist2(&t1, &t3);
  ek[7] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x08);
  aes_256_assist1(&t1, &t2);
  ek[8] = t1;
  aes_256_assist2(&t1, &t3);
  ek[9] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x10);
  aes_256_assist1(&t1, &t2);
  ek[10] = t1;
}

#define INIT_2WAY()                                                            \
  static const uint32_t table = 0x75310;                                       \
  const uint64_t tweak1_2[2] = {                                               \
      (state[0].hs.w[24] ^ (*((const uint64_t *)NONCE_POINTER(input0)))),      \
      (state[1].hs.w[24] ^ (*((const uint64_t *)NONCE_POINTER(input1))))};

// Requires 2x memory allocated in hp_state.
__attribute__((always_inline)) void
cryptonight_2way_hash(const void *input0, const void *input1, void *output0,
                      void *output1, const uint32_t memory,
                      const uint32_t iter_div, const uint32_t cn_aes_init) {
  union cn_slow_hash_state state[2];
  RDATA_ALIGN16 uint8_t text[INIT_SIZE_BYTE];
  hash_process(&state[0].hs, (const uint8_t *)input0, 64);
  hash_process(&state[1].hs, (const uint8_t *)input1, 64);

  uint8_t *fast_memory = hp_state + memory;

  size_t i;
  __m128i _a, _b, _c, _d, _f, _p, _q, _x;
  __m256i _a256, _b256, _p256, _q256, _c256, _x256;
  uint64_t hi, lo, hi2, lo2;
  RDATA_ALIGN16 uint8_t expandedKey[240];

  INIT_2WAY();

  // static const uint32_t table = 0x75310;
  const __m256i tweek = _mm256_set_epi64x(tweak1_2[1], 0, tweak1_2[0], 0);
  const __m256i AES_INT = _mm256_set_epi64x(0, cn_aes_init, 0, cn_aes_init);
  memcpy(text, state[0].init, INIT_SIZE_BYTE);
  aes_expand_key(state[0].hs.b, expandedKey);

  for (i = 0; i < memory / INIT_SIZE_BYTE; i++) {
    aes_pseudo_round(text, text, expandedKey, INIT_SIZE_BLK);

    memcpy(&hp_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
  }
  _a = _mm_xor_si128(
      _mm_loadu_si128((__m128i_u const *)&state[0].k[0]),
      _mm_loadu_si128((__m128i_u const *)&state[0].k[32])); // p23x2 p15
  _c = _mm_xor_si128(
      _mm_loadu_si128((__m128i_u const *)&state[0].k[16]),
      _mm_loadu_si128((__m128i_u const *)&state[0].k[48])); // p23x2 p15
  memcpy(text, state[1].init, INIT_SIZE_BYTE);
  aes_expand_key(state[1].hs.b, expandedKey);
  for (i = 0; i < memory / INIT_SIZE_BYTE; i++) {
    aes_pseudo_round(text, text, expandedKey, INIT_SIZE_BLK);

    memcpy(&fast_memory[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
  }
  _b = _mm_xor_si128(
      _mm_loadu_si128((__m128i_u const *)&state[1].k[0]),
      _mm_loadu_si128((__m128i_u const *)&state[1].k[32])); // p23x2 p15
  _d = _mm_xor_si128(
      _mm_loadu_si128((__m128i_u const *)&state[1].k[16]),
      _mm_loadu_si128((__m128i_u const *)&state[1].k[48])); // p23x2 p15
  _a256 = _mm256_set_m128i(_b, _a);                         // p5
  _b256 = _mm256_set_m128i(_d, _c);                         // p5
  for (i = 0; i < iter_div; i++) {
    /* Dependency chain: address -> read value ------+
     * written value <-+ hard function (AES or MUL) <+
     * next address  <-+
     */
    /* Iteration 1 */

    // PreAES
    // uint64_t j = state_index2(_mm256_extract_epi64(_a256,0));
    _x = _mm256_extractf128_si256(_a256, 1); // p5
    _x256 = _mm256_slli_epi64(
        _mm256_and_si256(_mm256_srli_epi64(_a256, 4), AES_INT),
        4); // p0->p15->p0
    const uint64_t k =
        _mm_cvtsi128_si64x(_mm256_extractf128_si256(_x256, 1)); // p5->p0
    const uint64_t j = _mm_cvtsi128_si64x(_mm256_castsi256_si128(_x256)); // p0
    _c = _mm_loadu_si128((__m128i_u const *)&hp_state[j]);                // p23
    _f = _mm_loadu_si128((__m128i_u const *)&fast_memory[k]);             // p23
    _c = _mm_aesenc_si128(_c, _mm256_castsi256_si128(_a256));             // p5
    _f = _mm_aesenc_si128(_f, _x);                                        // p5
    // PostAES
    _c256 = _mm256_set_m128i(_f, _c);       // p5
    _b256 = _mm256_xor_si256(_b256, _c256); // p15

    const uint64_t s =
        _mm_cvtsi128_si64x(_mm256_extractf128_si256(_c256, 1)); // p5->p0

    _x = _mm256_extractf128_si256(_b256, 1); // p5
    const uint8_t tmp =
        _mm_extract_epi8(_mm256_castsi256_si128(_b256), 11); // p4 p5 p237
    const uint8_t tmp2 = _mm_extract_epi8(_x, 11);           // p4 p5 p237
    const uint64_t r = _mm_cvtsi128_si64x(_mm256_castsi256_si128(_c256)); // p0
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; // ALU?
    _x256 = _mm256_slli_epi64(
        _mm256_and_si256(_mm256_srli_epi64(_c256, 4), AES_INT),
        4); // p0->p15->p0
    _b256 = _mm256_insert_epi8(_b256, tmp ^ ((table >> index) & 0x30),
                               11); // p4 p5 p237
    // const uint8_t tmp2 = _mm256_extract_epi8(_b256,27);
    const uint8_t index2 = (((tmp2 >> 3) & 6) | (tmp2 & 1)) << 1; // ALU?
    const uint64_t n =
        _mm_cvtsi128_si64x(_mm256_extractf128_si256(_x256, 1)); // p5->p0
    _b256 = _mm256_insert_epi8(_b256, tmp2 ^ ((table >> index2) & 0x30),
                               27); // p4 p5 p237
    const uint64_t m = _mm_cvtsi128_si64x(_mm256_castsi256_si128(_x256)); // p0
    _mm_storeu_si128((__m128i_u *)&hp_state[j],
                     _mm256_castsi256_si128(_b256));       // p4 p237
    _p = _mm_loadu_si128((__m128i_u const *)&hp_state[m]); // p23
    _mm_storeu_si128((__m128i_u *)&fast_memory[k],
                     _mm256_extracti128_si256(_b256, 1));     // p5-> p4 p237
    _q = _mm_loadu_si128((__m128i_u const *)&fast_memory[n]); // p23
    _b256 = _c256;

    const uint64_t l = _mm_cvtsi128_si64x(_p); // p0
    const uint64_t o = _mm_cvtsi128_si64x(_q); // p0
    _p256 = _mm256_set_m128i(_q, _p);          // p15

    __asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "1"(r), "rm"(l) : "cc"); // p6 p1
    __asm("mulq %3\n\t"
          : "=d"(hi2), "=a"(lo2)
          : "1"(s), "rm"(o)
          : "cc"); // p6 p1

    _q256 = _mm256_set_epi64x(lo2, hi2, lo, hi);

    _a256 = _mm256_add_epi64(_a256, _q256); // p15
    _q256 = _mm256_xor_si256(_a256, tweek); // p15
    _a256 = _mm256_xor_si256(_a256, _p256); // p15

    _mm_storeu_si128((__m128i_u *)&hp_state[m],
                     _mm256_castsi256_si128(_q256)); // p4 p237
    _mm_storeu_si128((__m128i_u *)&fast_memory[n],
                     _mm256_extracti128_si256(_q256, 1)); // p5-> p4 p237
  }

  memcpy(text, state[0].init, INIT_SIZE_BYTE);
  aes_expand_key(&state[0].hs.b[32], expandedKey);
  for (i = 0; i < memory / INIT_SIZE_BYTE; i++) {
    // add the xor to the pseudo round
    aes_pseudo_round_xor(text, text, expandedKey, &hp_state[i * INIT_SIZE_BYTE],
                         INIT_SIZE_BLK);
  }
  memcpy(state[0].init, text, INIT_SIZE_BYTE);

  memcpy(text, state[1].init, INIT_SIZE_BYTE);
  aes_expand_key(&state[1].hs.b[32], expandedKey);
  for (i = 0; i < memory / INIT_SIZE_BYTE; i++) {
    // add the xor to the pseudo round
    aes_pseudo_round_xor(text, text, expandedKey,
                         &fast_memory[i * INIT_SIZE_BYTE], INIT_SIZE_BLK);
  }
  memcpy(state[1].init, text, INIT_SIZE_BYTE);

  hash_permutation(&state[0].hs);
  extra_hashes[state[0].hs.b[0] & 3](&state[0], 200, output0);
  memset(output0 + 32, 0, 32);

  hash_permutation(&state[1].hs);
  extra_hashes[state[1].hs.b[0] & 3](&state[1], 200, output1);
  memset(output1 + 32, 0, 32);
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
                        32767);
}

void cryptonight_darklite_2way_hash(const void *input0, const void *input1,
                                    void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 524288, 131072,
                        16383);
}

void cryptonight_fast_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 2097152, 262144,
                        131071);
}

void cryptonight_lite_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 1048576, 262144,
                        65535);
}

void cryptonight_turtle_2way_hash(const void *input0, const void *input1,
                                  void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 262144, 65536, 16383);
}

void cryptonight_turtlelite_2way_hash(const void *input0, const void *input1,
                                      void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 262144, 65536, 8191);
}

#endif // __AVX2__ / 2way
