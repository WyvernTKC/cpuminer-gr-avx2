// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Portions Copyright (c) 2018 The Monero developers
// Portions Copyright (c) 2018 The TurtleCoin Developers

#include "cryptonight.h"
#include "algo/blake/sph_blake.h"
#include "algo/jh/sph_jh.h"
#include "algo/skein/sph_skein.h"
#include "crypto/c_keccak.h"
#include "simd-utils.h"
#include <immintrin.h>
#include <stdio.h>

#ifndef __AES__
#include "algo/groestl/sph_groestl.h"
#include "soft_aes.h"
#else
#include "algo/groestl/aes_ni/hash-groestl256.h"
#endif

extern __thread uint8_t *hp_state;

static void do_blake_hash(const void *input, void *output) {
  sph_blake256_context ctx __attribute__((aligned(64)));
  sph_blake256_init(&ctx);
  sph_blake256(&ctx, input, 200);
  sph_blake256_close(&ctx, output);
}

static void do_groestl_hash(const void *input, void *output) {
#ifdef __AES__
  hashState_groestl256 ctx __attribute__((aligned(64)));
  groestl256_full(&ctx, output, input, 1600);
#else
  sph_groestl256_context ctx __attribute__((aligned(64)));
  sph_groestl256_init(&ctx);
  sph_groestl256(&ctx, input, 200);
  sph_groestl256_close(&ctx, output);
#endif
}

static void do_jh_hash(const void *input, void *output) {
  sph_jh256_context ctx __attribute__((aligned(64)));
  sph_jh256_init(&ctx);
  sph_jh256(&ctx, input, 200);
  sph_jh256_close(&ctx, output);
}

static void do_skein_hash(const void *input, void *output) {
  sph_skein256_context ctx __attribute__((aligned(64)));
  sph_skein256_init(&ctx);
  sph_skein256(&ctx, input, 200);
  sph_skein256_close(&ctx, output);
}

static void (*const extra_hashes[4])(const void *, void *) = {
    do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};

// This will shift and xor tmp1 into
// itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static __attribute__((always_inline)) inline __m128i sl_xor(__m128i tmp1) {
  __m128i tmp4;
  tmp4 = _mm_slli_si128(tmp1, 0x04);
  tmp1 = _mm_xor_si128(tmp1, tmp4);
  tmp4 = _mm_slli_si128(tmp4, 0x04);
  tmp1 = _mm_xor_si128(tmp1, tmp4);
  tmp4 = _mm_slli_si128(tmp4, 0x04);
  tmp1 = _mm_xor_si128(tmp1, tmp4);
  return tmp1;
}

static __attribute__((always_inline)) inline void
aes_genkey_sub(__m128i *xout0, __m128i *xout2, const uint8_t rcon) {
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

#ifdef __VAES__

static void aes_genkey(const __m128i *memory, __m256i *k) {
  __m128i xout0 = _mm_load_si128(memory);
  __m128i xout2 = _mm_load_si128(memory + 1);
  k[0] = _mm256_set_m128i(xout0, xout0);
  k[1] = _mm256_set_m128i(xout2, xout2);

  aes_genkey_sub(&xout0, &xout2, 0x01);
  k[2] = _mm256_set_m128i(xout0, xout0);
  k[3] = _mm256_set_m128i(xout2, xout2);

  aes_genkey_sub(&xout0, &xout2, 0x02);
  k[4] = _mm256_set_m128i(xout0, xout0);
  k[5] = _mm256_set_m128i(xout2, xout2);

  aes_genkey_sub(&xout0, &xout2, 0x04);
  k[6] = _mm256_set_m128i(xout0, xout0);
  k[7] = _mm256_set_m128i(xout2, xout2);

  aes_genkey_sub(&xout0, &xout2, 0x08);
  k[8] = _mm256_set_m128i(xout0, xout0);
  k[9] = _mm256_set_m128i(xout2, xout2);
}

#else

static void aes_genkey(const __m128i *memory, __m128i *k) {
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

#endif

#ifdef __VAES__

static __attribute__((always_inline)) inline void aes_round(const __m256i *key,
                                                            __m256i *x) {
  x[0] = _mm256_aesenc_epi128(x[0], key[0]);
  x[0] = _mm256_aesenc_epi128(x[0], key[1]);
  x[0] = _mm256_aesenc_epi128(x[0], key[2]);
  x[0] = _mm256_aesenc_epi128(x[0], key[3]);
  x[0] = _mm256_aesenc_epi128(x[0], key[4]);
  x[0] = _mm256_aesenc_epi128(x[0], key[5]);
  x[0] = _mm256_aesenc_epi128(x[0], key[6]);
  x[0] = _mm256_aesenc_epi128(x[0], key[7]);
  x[0] = _mm256_aesenc_epi128(x[0], key[8]);
  x[0] = _mm256_aesenc_epi128(x[0], key[9]);
}

#elif defined(__AES__)

static __attribute__((always_inline)) inline void aes_round(const __m128i *key,
                                                            __m128i *x) {
  x[0] = _mm_aesenc_si128(x[0], key[0]);
  x[0] = _mm_aesenc_si128(x[0], key[1]);
  x[0] = _mm_aesenc_si128(x[0], key[2]);
  x[0] = _mm_aesenc_si128(x[0], key[3]);
  x[0] = _mm_aesenc_si128(x[0], key[4]);
  x[0] = _mm_aesenc_si128(x[0], key[5]);
  x[0] = _mm_aesenc_si128(x[0], key[6]);
  x[0] = _mm_aesenc_si128(x[0], key[7]);
  x[0] = _mm_aesenc_si128(x[0], key[8]);
  x[0] = _mm_aesenc_si128(x[0], key[9]);
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
  x[0] = soft_aesenc(x[0], key[0]);
  x[0] = soft_aesenc(x[0], key[1]);
  x[0] = soft_aesenc(x[0], key[2]);
  x[0] = soft_aesenc(x[0], key[3]);
  x[0] = soft_aesenc(x[0], key[4]);
  x[0] = soft_aesenc(x[0], key[5]);
  x[0] = soft_aesenc(x[0], key[6]);
  x[0] = soft_aesenc(x[0], key[7]);
  x[0] = soft_aesenc(x[0], key[8]);
  x[0] = soft_aesenc(x[0], key[9]);
}

#endif

#define PREFETCH_TYPE_R _MM_HINT_T0
#define PREFETCH_TYPE_W _MM_HINT_ET0
#define PREFETCH_W(ptr) _mm_prefetch(ptr, PREFETCH_TYPE_W)
#define PREFETCH_R(ptr) _mm_prefetch(ptr, PREFETCH_TYPE_R)

#define PF_TYPE_R 0
#define PF_TYPE_W 1
#define PF_LOCALITY 0
#define PREFETCH_W_SINGLE(ptr) __builtin_prefetch(ptr, PF_TYPE_W, PF_LOCALITY)
#define PREFETCH_R_SINGLE(ptr) __builtin_prefetch(ptr, PF_TYPE_R, PF_LOCALITY)

// Prefetch data. 4096 (4KiB) should allocate ~25% of most CPUs L1 Cache.
#define PREFETCH_SIZE_B 4096
#define PREFETCH_LINES 64  // (PREFETCH_SIZE_B / 64)
#define WPL 4              // Words per cache line.
#define WPS 8              // Words per state (128 bytes).
#define PREFETCH_SHIFT 256 // (PREFETCH_LINES * WPL)

#ifdef __VAES__

#define aes_batch(k, x)                                                        \
  aes_round(k, &x[0]);                                                         \
  aes_round(k, &x[1]);                                                         \
  aes_round(k, &x[2]);                                                         \
  aes_round(k, &x[3]);

#define xor_batch(dst, src)                                                    \
  dst[0] = _mm256_xor_si256(dst[0], src[0]);                                   \
  dst[1] = _mm256_xor_si256(dst[1], src[1]);                                   \
  dst[2] = _mm256_xor_si256(dst[2], src[2]);                                   \
  dst[3] = _mm256_xor_si256(dst[3], src[3]);

#else

#define aes_batch(k, x)                                                        \
  aes_round(k, &x[0]);                                                         \
  aes_round(k, &x[1]);                                                         \
  aes_round(k, &x[2]);                                                         \
  aes_round(k, &x[3]);                                                         \
  aes_round(k, &x[4]);                                                         \
  aes_round(k, &x[5]);                                                         \
  aes_round(k, &x[6]);                                                         \
  aes_round(k, &x[7]);

#define xor_batch(dst, src)                                                    \
  dst[0] = _mm_xor_si128(dst[0], src[0]);                                      \
  dst[1] = _mm_xor_si128(dst[1], src[1]);                                      \
  dst[2] = _mm_xor_si128(dst[2], src[2]);                                      \
  dst[3] = _mm_xor_si128(dst[3], src[3]);                                      \
  dst[4] = _mm_xor_si128(dst[4], src[4]);                                      \
  dst[5] = _mm_xor_si128(dst[5], src[5]);                                      \
  dst[6] = _mm_xor_si128(dst[6], src[6]);                                      \
  dst[7] = _mm_xor_si128(dst[7], src[7]);

#endif

static void explode_scratchpad(const __m128i *state, __m128i *ls,
                               const size_t memory) {
#ifdef __VAES__
  __m256i x[4] __attribute__((aligned(128)));
  __m256i k[10];
#else
  __m128i x[8] __attribute__((aligned(128)));
  __m128i k[10];
#endif

  aes_genkey(state, k);
#ifdef __VAES__
  const __m256i *key = k;
#else
  const __m128i *key = k;
#endif

  memcpy(x, state + 4, 128);

  size_t i;
  for (i = 0; i < PREFETCH_SHIFT; i += WPL) {
    PREFETCH_W_SINGLE(ls + i);
  }

  for (i = 0; i < memory - PREFETCH_SIZE_B; i += 128) {
    PREFETCH_W_SINGLE(ls + PREFETCH_SHIFT);
    PREFETCH_W_SINGLE(ls + PREFETCH_SHIFT + WPL);
#ifdef __VAES__
    aes_batch(key, x);
#else
    aes_batch(key, x);
#endif

    memcpy(ls, x, 128);
    ls += WPS;
  }

  for (; i < memory; i += 128) {
#ifdef __VAES__
    aes_batch(key, x);
#else
    aes_batch(key, x);
#endif

    memcpy(ls, x, 128);
    ls += WPS;
  }
}

static void implode_scratchpad(const __m128i *ls, __m128i *state,
                               const size_t memory) {
#ifdef __VAES__
  __m256i x[4] __attribute__((aligned(128)));
  __m256i k[10];
#else
  __m128i x[8] __attribute__((aligned(128)));
  __m128i k[10];
#endif

  aes_genkey(state + 2, k);

#ifdef __VAES__
  const __m256i *key = k;
#else
  const __m128i *key = k;
#endif

  memcpy(x, state + 4, 128);

  size_t i;
  for (i = 0; i < PREFETCH_SHIFT; i += WPL) {
    PREFETCH_R_SINGLE(ls + i);
  }

  for (i = 0; i < memory - PREFETCH_SIZE_B; i += 128) {
    PREFETCH_R_SINGLE(ls + PREFETCH_SHIFT);
    PREFETCH_R_SINGLE(ls + PREFETCH_SHIFT + WPL);
#ifdef __VAES__
    xor_batch(x, ((__m256i *)ls));
    aes_batch(key, x);
#else
    xor_batch(x, ls);
    aes_batch(key, x);
#endif

    ls += WPS;
  }

  for (; i < memory; i += 128) {
#ifdef __VAES__
    xor_batch(x, ((__m256i *)ls));
    aes_batch(key, x);
#else
    xor_batch(x, ls);
    aes_batch(key, x);
#endif

    ls += WPS;
  }

  memcpy(state + 4, x, 128);
}

static void implode_scratchpad_half(const __m128i *ls, __m128i *state,
                                    const size_t memory) {
#ifdef __VAES__
  __m256i x[4] __attribute__((aligned(128)));
  __m256i k[10];
#else
  __m128i x[8] __attribute__((aligned(128)));
  __m128i k[10];
#endif

  aes_genkey(state + 2, k);

#ifdef __VAES__
  const __m256i *key = k;
#else
  const __m128i *key = k;
#endif

  memcpy(x, state + 4, 128);

  size_t i;
  for (i = 0; i < PREFETCH_SHIFT; i += WPL) {
    PREFETCH_R_SINGLE(ls + i);
  }

  // First half is stored in memory.
  // The rest is unchanged by CN and can be calculated in place.
  for (i = 0; i < memory / 2 - PREFETCH_SIZE_B; i += 128) {
    PREFETCH_R_SINGLE(ls + PREFETCH_SHIFT);
    PREFETCH_R_SINGLE(ls + PREFETCH_SHIFT + WPL);
#ifdef __VAES__
    xor_batch(x, ((__m256i *)ls));
    aes_batch(key, x);
#else
    xor_batch(x, ls);
    aes_batch(key, x);
#endif

    ls += WPS;
  }

  for (; i < memory / 2; i += 128) {
#ifdef __VAES__
    xor_batch(x, ((__m256i *)ls));
    aes_batch(key, x);
#else
    xor_batch(x, ls);
    aes_batch(key, x);
#endif

    ls += WPS;
  }

#ifdef __VAES__
  __m256i x2[4] __attribute__((aligned(128)));
  __m256i k2[10];
#else
  __m128i x2[8] __attribute__((aligned(128)));
  __m128i k2[10];
#endif

  aes_genkey(state, k2);
#ifdef __VAES__
  const __m256i *key2 = k2;
#else
  const __m128i *key2 = k2;
#endif
  // Last x state from scratchpad explode is saved in the 128 bytes after
  // 1/2 of memory
  memcpy(x2, ls, 128);
#ifdef __VAES__
  aes_batch(key2, x2);
#else
  aes_batch(key2, x2);
#endif

  for (; i < memory; i += 128) {
#ifdef __VAES__
    xor_batch(x, x2);

    aes_batch(key, x);
    aes_batch(key2, x2);
#else
    xor_batch(x, x2);

    aes_batch(key, x);
    aes_batch(key2, x2);
#endif
  }

  memcpy(state + 4, x, 128);
}

#ifdef __AES__

#define AES(suffix)                                                            \
  register const __m128i cx##suffix = _mm_aesenc_si128(                        \
      *((const __m128i *)(&l##suffix[idx##suffix])), ax##suffix);

#else

#define AES(suffix)                                                            \
  register const __m128i cx##suffix =                                          \
      soft_aesenc(*(const __m128i *)(&l##suffix[idx##suffix]), ax##suffix);

#endif

#define AES_PF(suffix)                                                         \
  AES(suffix)                                                                  \
  const uint64_t idx2##suffix = cx##suffix[0] & mask;                          \
  PREFETCH_W((const char *)(l##suffix + idx2##suffix));

#define TWEAK(suffix)                                                          \
  {                                                                            \
    *(__m128i *)(&l##suffix[idx##suffix]) =                                    \
        _mm_xor_si128(bx##suffix, cx##suffix);                                 \
    bx##suffix = cx##suffix;                                                   \
                                                                               \
    register const uint32_t x =                                                \
        (uint8_t)(((uint64_t *)(&l##suffix[idx##suffix]))[1] >> 24);           \
    const uint8_t index = (((x >> 3) & 6) | (x & 1)) << 1;                     \
                                                                               \
    ((uint64_t *)(&l##suffix[idx##suffix]))[1] ^= ((0x7531 >> index) & 0x3)    \
                                                  << 28;                       \
  }

#define POST_AES(suffix)                                                       \
  {                                                                            \
    register const uint64_t cxl = cx##suffix[0];                               \
    register const uint64_t cl = ((uint64_t *)(&l##suffix[idx2##suffix]))[0];  \
    const uint64_t ch = ((uint64_t *)(&l##suffix[idx2##suffix]))[1];           \
                                                                               \
    {                                                                          \
      register uint64_t hi, lo;                                                \
      asm("mulq %[y]\n\t"                                                      \
          : "=d"(hi), "=a"(lo)                                                 \
          : "1"(cxl), [ y ] "ri"(cl)                                           \
          : "cc");                                                             \
                                                                               \
      ax##suffix[0] += hi;                                                     \
      ax##suffix[1] += lo;                                                     \
    }                                                                          \
                                                                               \
    ((uint64_t *)(&l##suffix[idx2##suffix]))[0] = ax##suffix[0];               \
    ((uint64_t *)(&l##suffix[idx2##suffix]))[1] =                              \
        ax##suffix[1] ^ tweak##suffix;                                         \
                                                                               \
    ax##suffix[0] ^= cl;                                                       \
    ax##suffix[1] ^= ch;                                                       \
  }                                                                            \
  idx##suffix = ax##suffix[0] & mask;

#define POST_AES_PF(suffix)                                                    \
  POST_AES(suffix)                                                             \
  PREFETCH_W((const char *)(l##suffix + idx##suffix));

#define CRYPTONIGHT_INIT(suffix)                                               \
  uint8_t state##suffix[200] __attribute__((aligned(16)));                     \
                                                                               \
  keccak1600(input##suffix, 64, state##suffix);                                \
                                                                               \
  uint64_t *h##suffix = (uint64_t *)state##suffix;                             \
  uint8_t *restrict l##suffix =                                                \
      __builtin_assume_aligned(&hp_state[suffix * shift], 128);                \
                                                                               \
  explode_scratchpad((const __m128i *)state##suffix, (__m128i *)l##suffix,     \
                     shift);                                                   \
  if (memory != shift) {                                                       \
    memcpy(&l##suffix[shift - 128], &l##suffix[shift - 256], 128);             \
  }                                                                            \
                                                                               \
  const uint64_t tweak##suffix =                                               \
      (*((uint64_t *)(&((uint8_t *)input##suffix)[35]))) ^ h##suffix[24];      \
                                                                               \
  register __m128i ax##suffix =                                                \
      _mm_set_epi64x((int64_t)(h##suffix[1] ^ h##suffix[5]),                   \
                     (int64_t)(h##suffix[0] ^ h##suffix[4]));                  \
  uint64_t idx##suffix = ax##suffix[0] & mask;                                 \
                                                                               \
  __m128i bx##suffix = _mm_set_epi64x((int64_t)(h##suffix[3] ^ h##suffix[7]),  \
                                      (int64_t)(h##suffix[2] ^ h##suffix[6]));

#define CRYPTONIGHT_FINISH(suffix)                                             \
  if (memory == shift) {                                                       \
    implode_scratchpad((const __m128i *)l##suffix, (__m128i *)state##suffix,   \
                       memory);                                                \
  } else {                                                                     \
    implode_scratchpad_half((const __m128i *)l##suffix,                        \
                            (__m128i *)state##suffix, memory);                 \
  }                                                                            \
  keccakf(h##suffix, 24);                                                      \
  extra_hashes[state##suffix[0] & 3](state##suffix, output##suffix);           \
  memset(&((uint8_t *)output##suffix)[32], 0, 32);

static __attribute__((always_inline)) inline void
cryptonight_hash(const void *input0, void *output0, const uint32_t memory,
                 const int iterations, const uint64_t mask,
                 const uint32_t shift) {
  CRYPTONIGHT_INIT(0);

  for (int i = 0; i < iterations; ++i) {
    // AES
    AES(0);
    TWEAK(0);

    // Post AES
    const uint64_t idx20 = cx0[0] & mask;
    POST_AES(0);
  }

  CRYPTONIGHT_FINISH(0);
}

// Variant      MEMORY            ITERATIONS      MASK
// Turtlelite   256KiB*, 2^18     2^16            (MEMORY - 16) / 2
// Turtle       256KiB,  2^18     2^16            (MEMORY - 16)
// Darklite     512KiB*, 2^19     2^17            (MEMORY - 16) / 2
// Dark         512KiB,  2^19     2^17            (MEMORY - 16)
// Lite         1MiB,    2^20     2^18            (MEMORY - 16)
// Fast         2MiB,    2^21     2^18            (MEMORY - 16)
// Turtlelite / Darklite requires memory / 2 of their main variant but still
// needs to calculate the 2nd half, can be done in the end without use of the
// half of the required memory.
void cryptonight_turtlelite_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 262144, 65536, 131056, 131200);
}

void cryptonight_turtle_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 262144, 65536, 262128, 262144);
}

void cryptonight_darklite_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 524288, 131072, 262128, 262272);
}

void cryptonight_dark_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 524288, 131072, 524272, 524288);
}

void cryptonight_lite_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 1048576, 262144, 1048560, 1048576);
}

void cryptonight_fast_hash(const void *input, void *output) {
  cryptonight_hash(input, output, 2097152, 262144, 2097136, 2097152);
}

// Requires 2x memory allocated in hp_state.
static __attribute__((always_inline)) inline void
cryptonight_2way_hash(const void *input0, const void *input1, void *output0,
                      void *output1, const uint32_t memory,
                      const int iterations, const uint64_t mask,
                      const uint32_t shift) {
  CRYPTONIGHT_INIT(0);
  CRYPTONIGHT_INIT(1);

  for (int i = 0; i < iterations; ++i) {
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

// Variant      MEMORY            ITERATIONS      MASK
// Turtlelite   256KiB*, 2^18     2^16            (MEMORY - 16) / 2
// Turtle       256KiB,  2^18     2^16            (MEMORY - 16)
// Darklite     512KiB*, 2^19     2^17            (MEMORY - 16) / 2
// Dark         512KiB,  2^19     2^17            (MEMORY - 16)
// Lite         1MiB,    2^20     2^18            (MEMORY - 16)
// Fast         2MiB,    2^21     2^18            (MEMORY - 16)
// Turtlelite / Darklite requires memory / 2 of their main variant but still
// needs to calculate the 2nd half, can be done in the end without use of the
// half of the required memory.
void cryptonight_turtlelite_2way_hash(const void *input0, const void *input1,
                                      void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 262144, 65536, 131056,
                        131200);
}

void cryptonight_turtle_2way_hash(const void *input0, const void *input1,
                                  void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 262144, 65536, 262128,
                        262144);
}

void cryptonight_darklite_2way_hash(const void *input0, const void *input1,
                                    void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 524288, 131072,
                        262128, 262272);
}

void cryptonight_dark_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 524288, 131072,
                        524272, 524288);
}

void cryptonight_lite_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 1048576, 262144,
                        1048560, 1048576);
}

void cryptonight_fast_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1) {
  cryptonight_2way_hash(input0, input1, output0, output1, 2097152, 262144,
                        2097136, 2097152);
}

#ifdef __AVX2__

// Requires 4x memory allocated in hp_state.
static __attribute__((always_inline)) inline void
cryptonight_4way_hash(const void *input0, const void *input1,
                      const void *input2, const void *input3, void *output0,
                      void *output1, void *output2, void *output3,
                      const uint32_t memory, const int iterations,
                      const uint64_t mask, const uint32_t shift) {
  CRYPTONIGHT_INIT(0);
  CRYPTONIGHT_INIT(1);
  CRYPTONIGHT_INIT(2);
  CRYPTONIGHT_INIT(3);

  for (int i = 0; i < iterations; ++i) {
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

// Variant      MEMORY            ITERATIONS      MASK
// Turtlelite   256KiB*, 2^18     2^16            (MEMORY - 16) / 2
// Turtle       256KiB,  2^18     2^16            (MEMORY - 16)
// Darklite     512KiB*, 2^19     2^17            (MEMORY - 16) / 2
// Dark         512KiB,  2^19     2^17            (MEMORY - 16)
// Lite         1MiB,    2^20     2^18            (MEMORY - 16)
// Fast         2MiB,    2^21     2^18            (MEMORY - 16)
// Turtlelite / Darklite requires memory / 2 of their main variant but still
// needs to calculate the 2nd half, can be done in the end without use of the
// half of the required memory.
void cryptonight_turtlelite_4way_hash(const void *input0, const void *input1,
                                      const void *input2, const void *input3,
                                      void *output0, void *output1,
                                      void *output2, void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 262144, 65536, 131056, 131200);
}

void cryptonight_turtle_4way_hash(const void *input0, const void *input1,
                                  const void *input2, const void *input3,
                                  void *output0, void *output1, void *output2,
                                  void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 262144, 65536, 262128, 262144);
}

void cryptonight_darklite_4way_hash(const void *input0, const void *input1,
                                    const void *input2, const void *input3,
                                    void *output0, void *output1, void *output2,
                                    void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 524288, 131072, 262128, 262272);
}

void cryptonight_dark_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 524288, 131072, 524272, 524288);
}

void cryptonight_lite_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 1048576, 262144, 1048560, 1048576);
}

void cryptonight_fast_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3) {
  cryptonight_4way_hash(input0, input1, input2, input3, output0, output1,
                        output2, output3, 2097152, 262144, 2097136, 2097152);
}

#endif // AVX2
