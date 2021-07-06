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
#include "crypto/hash-ops.h"
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
  int r = skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t *)output);
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

static inline void aes_genkey(const __m128i *memory, __m128i *k) {
  __m128i xout0 = _mm_load_si128(memory);
  __m128i xout2 = _mm_load_si128(memory + 1);
  k[0] = xout0;
  k[1] = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x01);
  k[2] = xout0;
  k[3] = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x02);
  k[4] = xout0;
  k[5] = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x04);
  k[6] = xout0;
  k[7] = xout2;

  aes_genkey_sub(&xout0, &xout2, 0x08);
  k[8] = xout0;
  k[9] = xout2;
}

#ifdef __AES__

static __attribute__((always_inline)) inline void aes_round(const __m128i *key,
                                                            __m128i *x) {
  x[0] = _mm_aesenc_si128(x[0], *key);
  x[1] = _mm_aesenc_si128(x[1], *key);
  x[2] = _mm_aesenc_si128(x[2], *key);
  x[3] = _mm_aesenc_si128(x[3], *key);
  x[4] = _mm_aesenc_si128(x[4], *key);
  x[5] = _mm_aesenc_si128(x[5], *key);
  x[6] = _mm_aesenc_si128(x[6], *key);
  x[7] = _mm_aesenc_si128(x[7], *key);
}

#else

static __attribute__((always_inline)) inline __m128i
soft_aesenc(const __m128i in, const __m128i key) {
  // saes_table is implemented in "soft_aes.h"
  const uint32_t x0 = ((uint32_t *)(&in))[0];
  const uint32_t x1 = ((uint32_t *)(&in))[1];
  const uint32_t x2 = ((uint32_t *)(&in))[2];
  const uint32_t x3 = ((uint32_t *)(&in))[3];

  return _mm_xor_si128(
      _mm_set_epi32(
          (saes_table[0][(uint8_t)x3] ^ saes_table[1][(uint8_t)(x0 >> 8)] ^
           saes_table[2][(uint8_t)(x1 >> 16)] ^
           saes_table[3][(uint8_t)(x2 >> 24)]),
          (saes_table[0][(uint8_t)x2] ^ saes_table[1][(uint8_t)(x3 >> 8)] ^
           saes_table[2][(uint8_t)(x0 >> 16)] ^
           saes_table[3][(uint8_t)(x1 >> 24)]),
          (saes_table[0][(uint8_t)x1] ^ saes_table[1][(uint8_t)(x2 >> 8)] ^
           saes_table[2][(uint8_t)(x3 >> 16)] ^
           saes_table[3][(uint8_t)(x0 >> 24)]),
          (saes_table[0][(uint8_t)x0] ^ saes_table[1][(uint8_t)(x1 >> 8)] ^
           saes_table[2][(uint8_t)(x2 >> 16)] ^
           saes_table[3][(uint8_t)(x3 >> 24)])),
      key);
}

static __attribute__((always_inline)) inline void aes_round(const __m128i *key,
                                                            __m128i *x) {
  x[0] = soft_aesenc(x[0], *key);
  x[1] = soft_aesenc(x[1], *key);
  x[2] = soft_aesenc(x[2], *key);
  x[3] = soft_aesenc(x[3], *key);
  x[4] = soft_aesenc(x[4], *key);
  x[5] = soft_aesenc(x[5], *key);
  x[6] = soft_aesenc(x[6], *key);
  x[7] = soft_aesenc(x[7], *key);
}

#endif

#define PREFETCH_TYPE_R _MM_HINT_T0
#define PREFETCH_TYPE_W _MM_HINT_ET0

// Prefetch data. 4096 (4KiB) should allocate ~25% of most CPUs L1 Cache.
#define PREFETCH_SIZE_B 4096
#define PREFETCH_LINES 64  // (PREFETCH_SIZE_B / 64)
#define WPL 4              // Words per cache line.
#define WPS 8              // Words per state (128 bytes).
#define PREFETCH_SHIFT 256 // (PREFETCH_LINES * WPL)

#define aes_batch(k, x)                                                        \
  aes_round(&k[0], x);                                                         \
  aes_round(&k[1], x);                                                         \
  aes_round(&k[2], x);                                                         \
  aes_round(&k[3], x);                                                         \
  aes_round(&k[4], x);                                                         \
  aes_round(&k[5], x);                                                         \
  aes_round(&k[6], x);                                                         \
  aes_round(&k[7], x);                                                         \
  aes_round(&k[8], x);                                                         \
  aes_round(&k[9], x);

static inline void explode_scratchpad(const __m128i *state, __m128i *ls,
                                      const size_t memory) {
  __m128i x[8];
  __m128i k[10];

  aes_genkey(state, k);
  const __m128i *key = __builtin_assume_aligned(k, 16);

  memcpy(x, state + 4, 128);

  size_t i;
  for (i = 0; i < PREFETCH_SHIFT; i += WPL) {
    _mm_prefetch(ls + i, PREFETCH_TYPE_W);
  }

  for (i = 0; i < memory - PREFETCH_SIZE_B; i += 128) {
    aes_batch(key, x);

    _mm_prefetch(ls + PREFETCH_SHIFT, PREFETCH_TYPE_W);
    _mm_prefetch(ls + PREFETCH_SHIFT + WPL, PREFETCH_TYPE_W);
    memcpy(ls, x, 128);
    ls += WPS;
  }

  for (; i < memory; i += 128) {
    aes_batch(key, x);

    memcpy(ls, x, 128);
    ls += WPS;
  }
}

static inline void implode_scratchpad(const __m128i *ls, __m128i *state,
                                      const size_t memory) {
  __m128i x[8];
  __m128i k[10];

  aes_genkey(state + 2, k);
  const __m128i *key = __builtin_assume_aligned(k, 16);

  memcpy(x, state + 4, 128);

  size_t i;
  for (i = 0; i < PREFETCH_SHIFT; i += WPL) {
    _mm_prefetch(ls + i, PREFETCH_TYPE_R);
  }

  for (i = 0; i < memory - PREFETCH_SIZE_B; i += 128) {
    _mm_prefetch(ls + PREFETCH_SHIFT, PREFETCH_TYPE_R);
    _mm_prefetch(ls + PREFETCH_SHIFT + WPL, PREFETCH_TYPE_R);
    x[0] = _mm_xor_si128(ls[0], x[0]);
    x[1] = _mm_xor_si128(ls[1], x[1]);
    x[2] = _mm_xor_si128(ls[2], x[2]);
    x[3] = _mm_xor_si128(ls[3], x[3]);
    x[4] = _mm_xor_si128(ls[4], x[4]);
    x[5] = _mm_xor_si128(ls[5], x[5]);
    x[6] = _mm_xor_si128(ls[6], x[6]);
    x[7] = _mm_xor_si128(ls[7], x[7]);
    ls += WPS;

    aes_batch(key, x);
  }

  for (; i < memory; i += 128) {
    x[0] = _mm_xor_si128(ls[0], x[0]);
    x[1] = _mm_xor_si128(ls[1], x[1]);
    x[2] = _mm_xor_si128(ls[2], x[2]);
    x[3] = _mm_xor_si128(ls[3], x[3]);
    x[4] = _mm_xor_si128(ls[4], x[4]);
    x[5] = _mm_xor_si128(ls[5], x[5]);
    x[6] = _mm_xor_si128(ls[6], x[6]);
    x[7] = _mm_xor_si128(ls[7], x[7]);
    ls += WPS;

    aes_batch(key, x);
  }

  memcpy(state + 4, x, 128);
}

#ifdef __AES__

#define AES(suffix)                                                            \
  const __m128i cx##suffix = _mm_aesenc_si128(                                 \
      _mm_load_si128((const __m128i *)(&l##suffix[idx##suffix])),              \
      _mm_set_epi64x((int64_t)ah##suffix, (int64_t)al##suffix));

#else

#define AES(suffix)                                                            \
  const __m128i cx##suffix =                                                   \
      soft_aesenc(_mm_load_si128((const __m128i *)(&l##suffix[idx##suffix])),  \
                  _mm_set_epi64x((int64_t)ah##suffix, (int64_t)al##suffix));

#endif

#define AES_PF(suffix)                                                         \
  AES(suffix)                                                                  \
  _mm_prefetch(&l##suffix[((uint64_t)cx##suffix[0]) & mask], PREFETCH_TYPE_W);

#define TWEAK(suffix)                                                          \
  {                                                                            \
    const __m128i tmp = _mm_xor_si128(bx##suffix, cx##suffix);                 \
    bx##suffix = cx##suffix;                                                   \
                                                                               \
    register const uint64_t vh = (uint64_t)tmp[1];                             \
                                                                               \
    const uint8_t x = (uint8_t)(vh >> 24);                                     \
    const uint8_t index = (((x >> (3)) & 6) | (x & 1)) << 1;                   \
                                                                               \
    ((uint64_t *)(&l##suffix[idx##suffix]))[0] = (uint64_t)tmp[0];             \
    ((uint64_t *)(&l##suffix[idx##suffix]))[1] =                               \
        vh ^ (((((uint16_t)0x7531) >> index) & 0x3) << 28);                    \
  }

#define POST_AES(suffix)                                                       \
  const uint64_t cxl##suffix = (uint64_t)cx##suffix[0];                        \
  idx##suffix = cxl##suffix & mask;                                            \
                                                                               \
  {                                                                            \
    register const uint64_t cl = ((uint64_t *)(&l##suffix[idx##suffix]))[0];   \
    const uint64_t ch = ((uint64_t *)(&l##suffix[idx##suffix]))[1];            \
                                                                               \
    {                                                                          \
      register uint64_t hi, lo;                                                \
      __asm("mulq %3\n\t"                                                      \
            : "=d"(hi), "=a"(lo)                                               \
            : "1"(cxl##suffix), "rm"(cl)                                       \
            : "cc");                                                           \
                                                                               \
      al##suffix += hi;                                                        \
      ah##suffix += lo;                                                        \
    }                                                                          \
                                                                               \
    ((uint64_t *)(&l##suffix[idx##suffix]))[0] = al##suffix;                   \
    ((uint64_t *)(&l##suffix[idx##suffix]))[1] = ah##suffix ^ tweak##suffix;   \
                                                                               \
    al##suffix ^= cl;                                                          \
    ah##suffix ^= ch;                                                          \
  }                                                                            \
  idx##suffix = al##suffix & mask;

#define POST_AES_PF(suffix)                                                    \
  POST_AES(suffix)                                                             \
  _mm_prefetch(&l##suffix[idx##suffix], PREFETCH_TYPE_W);

#define CRYPTONIGHT_INIT(suffix)                                               \
  uint8_t state##suffix[200] __attribute__((aligned(16)));                     \
                                                                               \
  keccak1600(input##suffix, 64, state##suffix);                                \
                                                                               \
  uint64_t *h##suffix = (uint64_t *)state##suffix;                             \
  uint8_t *restrict l##suffix =                                                \
      __builtin_assume_aligned(hp_state + (suffix * memory), 16);              \
                                                                               \
  explode_scratchpad((const __m128i *)state##suffix, (__m128i *)l##suffix,     \
                     memory);                                                  \
                                                                               \
  const uint64_t tweak##suffix =                                               \
      (*((uint64_t *)(&((uint8_t *)input##suffix)[35]))) ^ h##suffix[24];      \
                                                                               \
  uint64_t al##suffix = h##suffix[0] ^ h##suffix[4];                           \
  uint64_t ah##suffix = h##suffix[1] ^ h##suffix[5];                           \
  uint64_t idx##suffix = al##suffix & mask;                                    \
                                                                               \
  __m128i bx##suffix = _mm_set_epi64x((int64_t)(h##suffix[3] ^ h##suffix[7]),  \
                                      (int64_t)(h##suffix[2] ^ h##suffix[6]));

#define CRYPTONIGHT_FINISH(suffix)                                             \
  implode_scratchpad((const __m128i *)l##suffix, (__m128i *)state##suffix,     \
                     memory);                                                  \
  keccakf(h##suffix, 24);                                                      \
  extra_hashes[state##suffix[0] & 3](state##suffix, 200, output##suffix);      \
  memset(&((uint8_t *)output##suffix)[32], 0, 32);

static __attribute__((always_inline)) inline void
cryptonight_hash(const void *input0, void *output0, const uint32_t memory,
                 const uint32_t iterations, const uint32_t mask) {
  CRYPTONIGHT_INIT(0);

  for (size_t i = 0; i < iterations; ++i) {
    // AES
    AES(0);
    TWEAK(0);

    // Post AES
    POST_AES(0);
  }

  CRYPTONIGHT_FINISH(0);
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

// Requires 2x memory allocated in hp_state.
static inline void cryptonight_2way_hash(const void *input0, const void *input1,
                                         void *output0, void *output1,
                                         const uint32_t memory,
                                         const uint32_t iterations,
                                         const uint32_t mask) {
  CRYPTONIGHT_INIT(0);
  CRYPTONIGHT_INIT(1);

  for (size_t i = 0; i < iterations; ++i) {
    // AES
    AES_PF(0);
    AES_PF(1);

    TWEAK(0);
    TWEAK(1);

    POST_AES_PF(0);
    POST_AES_PF(1);
  }

  CRYPTONIGHT_FINISH(0);
  CRYPTONIGHT_FINISH(1);
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

#ifdef __AVX2__

// Requires 4x memory allocated in hp_state.
static inline void cryptonight_4way_hash(const void *input0, const void *input1,
                                         const void *input2, const void *input3,
                                         void *output0, void *output1,
                                         void *output2, void *output3,
                                         const uint32_t memory,
                                         const uint32_t iterations,
                                         const uint32_t mask) {
  CRYPTONIGHT_INIT(0);
  CRYPTONIGHT_INIT(1);
  CRYPTONIGHT_INIT(2);
  CRYPTONIGHT_INIT(3);

  for (size_t i = 0; i < iterations; ++i) {
    // AES
    AES_PF(0);
    AES_PF(1);
    AES_PF(2);
    AES_PF(3);

    TWEAK(0);
    TWEAK(1);
    TWEAK(2);
    TWEAK(3);

    POST_AES_PF(0);
    POST_AES_PF(1);
    POST_AES_PF(2);
    POST_AES_PF(3);
  }

  CRYPTONIGHT_FINISH(0);
  CRYPTONIGHT_FINISH(1);
  CRYPTONIGHT_FINISH(2);
  CRYPTONIGHT_FINISH(3);
}

// Variant      MEMORY            ITERATIONS      CN_AES_INIT
// Dark         512KiB, 2^19      2^17            (MEMORY - 16)
// Darklite     512KiB, 2^19      2^17            (MEMORY - 16) / 2
// Fast         2MiB,   2^21      2^18            (MEMORY - 16)
// Lite         1Mib,   2^20      2^18            (MEMORY - 16)
// Turtle       256KiB, 2^18      2^16            (MEMORY - 16)
// Turtlelite   256KiB, 2^18      2^16            (MEMORY - 16) / 2
void cryptonight_dark_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 524288, 131072, 524272);
}

void cryptonight_darklite_4way_hash(const void *input0, const void *input1,
                                    const void *input2, const void *input3,
                                    void *output0, void *output1, void *output2,
                                    void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 524288, 131072, 262128);
}

void cryptonight_fast_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 2097152, 262144, 2097136);
}

void cryptonight_lite_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 1048576, 262144, 1048560);
}

void cryptonight_turtle_4way_hash(const void *input0, const void *input1,
                                  const void *input2, const void *input3,
                                  void *output0, void *output1, void *output2,
                                  void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 262144, 65536, 262128);
}

void cryptonight_turtlelite_4way_hash(const void *input0, const void *input1,
                                      const void *input2, const void *input3,
                                      void *output0, void *output1,
                                      void *output2, void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 262144, 65536, 131056);
}

#endif // AVX2
