// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Portions Copyright (c) 2018 The Monero developers
// Portions Copyright (c) 2018 The TurtleCoin Developers

#include <stdio.h>
#include <stdlib.h>
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"
#include "crypto/variant2_int_sqrt.h"

#if defined(_MSC_VER)
#include <malloc.h>
#endif

#define MEMORY          524288 /* 512KB - 2^19 */
#define ITER            262144 /* 2^18 */
#define ITER_DIV        131072 /* 2^17 */
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE  (INIT_SIZE_BLK * AES_BLOCK_SIZE)
#define CN_INIT         (MEMORY / INIT_SIZE_BYTE)
#define CN_AES_INIT     (MEMORY / AES_BLOCK_SIZE) / 2
#include <wmmintrin.h>
#include <sys/mman.h>
#define STATIC static
#define INLINE inline
#define RDATA_ALIGN16 __attribute__ ((aligned(16)))
#define R128(x) ((__m128i *) (x))
#if defined(__INTEL_COMPILER)
#define ASM __asm__
#elif !defined(_MSC_VER)
#define ASM __asm__
#else
#define ASM __asm
#endif

#define state_index(x) (((*((uint64_t *)x) >> 4) & (CN_AES_INIT - 1)) << 4)
/*#define VARIANT1_1(p) \
  do if (variant == 1) \
  { \
    const uint8_t tmp = ((const uint8_t*)(p))[11]; \
    static const uint32_t table = 0x75310; \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
  } while(0)

#define VARIANT1_2(p) \
   do if (variant == 1) \
   { \
     ((uint64_t*)p)[1] ^= tweak1_2; \
   } while(0)
*/

#define VARIANT1_1(p) \
  do if (variant > 0) \
  { \
    const uint8_t tmp = ((const uint8_t*)(p))[11]; \
    static const uint32_t table = 0x75310; \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
  } while(0)

#define VARIANT1_2(p) \
  do if (variant > 0) \
  { \
    xor64(p, tweak1_2); \
  } while(0)

#define VARIANT1_CHECK() \
  do if (len < 43) \
  { \
    fprintf(stderr, "Cryptonight variants need at least 43 bytes of data"); \
    _exit(1); \
  } while(0)

#define NONCE_POINTER (((const uint8_t*)input)+35)

#define VARIANT1_INIT() \
  if (variant > 0) \
  { \
    VARIANT1_CHECK(); \
  } \
  const uint64_t tweak1_2 = variant > 0 ? (ctx->state.hs.w[24] ^ (*((const uint64_t*)NONCE_POINTER))) : 0

/*#define VARIANT1_INIT() \
  if (variant == 1 && len < 43) \
  { \
    fprintf(stderr, "Cryptonight variant 1 needs at least 43 bytes of data"); \
    _exit(1); \
  } \
  const uint64_t tweak1_2 = (variant == 1) ? *(const uint64_t*)(((const uint8_t*)input)+35) ^ ctx->state.hs.w[24] : 0
*/

#define U64(p) ((uint64_t*)(p))

#define VARIANT2_INIT(b, state) \
  uint64_t division_result; \
  uint64_t sqrt_result; \
  do if (variant >= 2) \
  { \
    U64(b)[2] = state.hs.w[8] ^ state.hs.w[10]; \
    U64(b)[3] = state.hs.w[9] ^ state.hs.w[11]; \
    division_result = state.hs.w[12]; \
    sqrt_result = state.hs.w[13]; \
  } while (0)

#define VARIANT2_SHUFFLE_ADD(base_ptr, offset, a, b) \
  do if (variant >= 2) \
  { \
    uint64_t* chunk1 = U64((base_ptr) + ((offset) ^ 0x10)); \
    uint64_t* chunk2 = U64((base_ptr) + ((offset) ^ 0x20)); \
    uint64_t* chunk3 = U64((base_ptr) + ((offset) ^ 0x30)); \
    \
    const uint64_t chunk1_old[2] = { chunk1[0], chunk1[1] }; \
    \
    chunk1[0] = chunk3[0] + U64(b + 16)[0]; \
    chunk1[1] = chunk3[1] + U64(b + 16)[1]; \
    \
    chunk3[0] = chunk2[0] + U64(a)[0]; \
    chunk3[1] = chunk2[1] + U64(a)[1]; \
    \
    chunk2[0] = chunk1_old[0] + U64(b)[0]; \
    chunk2[1] = chunk1_old[1] + U64(b)[1]; \
  } while (0)

#define VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr) \
  ((uint64_t*)(b))[0] ^= division_result ^ (sqrt_result << 32); \
  { \
    const uint64_t dividend = ((uint64_t*)(ptr))[1]; \
    const uint32_t divisor = (((uint32_t*)(ptr))[0] + (uint32_t)(sqrt_result << 1)) | 0x80000001UL; \
    division_result = ((uint32_t)(dividend / divisor)) + \
                     (((uint64_t)(dividend % divisor)) << 32); \
  } \
  const uint64_t sqrt_input = ((uint64_t*)(ptr))[0] + division_result

#define VARIANT2_INTEGER_MATH(b, ptr) \
    do if (variant >= 2) \
    { \
      VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr); \
      VARIANT2_INTEGER_MATH_SQRT_STEP_FP64(); \
      VARIANT2_INTEGER_MATH_SQRT_FIXUP(sqrt_result); \
    } while (0)

#define VARIANT2_2() \
  do if (variant >= 2) { \
    ((uint64_t*)(hp_state + ((j * AES_BLOCK_SIZE) ^ 0x10)))[0] ^= hi; \
    ((uint64_t*)(hp_state + ((j * AES_BLOCK_SIZE) ^ 0x10)))[1] ^= lo; \
    hi ^= ((uint64_t*)(hp_state + ((j * AES_BLOCK_SIZE) ^ 0x20)))[0]; \
    lo ^= ((uint64_t*)(hp_state + ((j * AES_BLOCK_SIZE) ^ 0x20)))[1]; \
  } while (0)

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};
#pragma pack(pop)

static void do_dark_lite_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_dark_lite_groestl_hash(const void* input, size_t len, char* output) {
    groestl(input, len * 8, (uint8_t*)output);
}

static void do_dark_lite_jh_hash(const void* input, size_t len, char* output) {
    int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
    assert(SUCCESS == r);
}

static void do_dark_lite_skein_hash(const void* input, size_t len, char* output) {
    int r = c_skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
    assert(SKEIN_SUCCESS == r);
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
    do_dark_lite_blake_hash, do_dark_lite_groestl_hash, do_dark_lite_jh_hash, do_dark_lite_skein_hash
};

extern int aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

static inline size_t e2i(const uint8_t* a) {
    return (*((uint64_t*) a) / AES_BLOCK_SIZE) & (CN_AES_INIT - 1);
}

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
	((uint64_t*) res)[1] = mul128(((uint64_t*) a)[0], ((uint64_t*) b)[0], (uint64_t*) res);
	//ASM("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "%a" (a), "rm" (b) : "cc");
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
    uint64_t a0, a1, b0, b1;

    a0 = SWAP64LE(((uint64_t*) a)[0]);
    a1 = SWAP64LE(((uint64_t*) a)[1]);
    b0 = SWAP64LE(((uint64_t*) b)[0]);
    b1 = SWAP64LE(((uint64_t*) b)[1]);
    a0 += b0;
    a1 += b1;
    ((uint64_t*) a)[0] = SWAP64LE(a0);
    ((uint64_t*) a)[1] = SWAP64LE(a1);
}

static inline void copy_block(uint8_t* dst, const uint8_t* src) {
    ((uint64_t*) dst)[0] = ((uint64_t*) src)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) src)[1];
}

static void swap_blocks(uint8_t* a, uint8_t* b) {
    size_t i;
    uint8_t t;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
}

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
    ((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
    ((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
    ((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
}

static inline void xor64(uint64_t *a, const uint64_t b)
{
    *a ^= b;
}

extern __thread uint8_t *hp_state;
extern __thread int hp_allocated;



struct cryptonightdarklite_ctx {
    uint8_t long_state[MEMORY];
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE];
    /*uint8_t a[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE * 2];
    uint8_t c[AES_BLOCK_SIZE];*/
	RDATA_ALIGN16 uint64_t a[2];
	RDATA_ALIGN16 uint64_t b[2];
	RDATA_ALIGN16 uint64_t c[2];
    uint8_t aes_key[AES_KEY_SIZE];
    oaes_ctx* aes_ctx;
};

static inline void aesni_pseudo_round(const uint8_t *in, uint8_t *out,
                                      const uint8_t *expandedKey)
{
    __m128i *k = R128(expandedKey);
    __m128i d;

    d = _mm_loadu_si128(R128(in));
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
    _mm_storeu_si128((R128(out)), d);
}

static inline void aes_pseudo_round(const uint8_t *in, uint8_t *out,
                                    const uint8_t *expandedKey, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i d;
    int i;

    for(i = 0; i < nblocks; i++)
    {
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

static inline void aesni_pseudo_round_xor(const uint8_t *in, uint8_t *out,
                                        const uint8_t *expandedKey, const uint8_t *xor)
{
    __m128i *k = R128(expandedKey);
    __m128i *x = R128(xor);
    __m128i d;

        d = _mm_loadu_si128(R128(in));
        d = _mm_xor_si128(d, *R128(x));
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
        _mm_storeu_si128((R128(out)), d);
}

static inline void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out,
                                        const uint8_t *expandedKey, const uint8_t *xor, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i *x = R128(xor);
    __m128i d;
    int i;

    for(i = 0; i < nblocks; i++)
    {
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

static inline void aes_256_assist1(__m128i* t1, __m128i * t2)
{
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

static inline void aes_256_assist2(__m128i* t1, __m128i * t3)
{
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

static inline void aes_expand_key(const uint8_t *key, uint8_t *expandedKey)
{
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

void cryptonightdarklite_hash(const char* input, char* output, uint32_t len, int variant) {
#if defined(_MSC_VER)
    struct cryptonightdarklite_ctx *ctx = _malloca(sizeof(struct cryptonightdarklite_ctx));
#else
    struct cryptonightdarklite_ctx *ctx = alloca(sizeof(struct cryptonightdarklite_ctx));
#endif
    hash_process(&ctx->state.hs, (const uint8_t*) input, len);
    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    //memcpy(ctx->aes_key, ctx->state.hs.b, AES_KEY_SIZE);
    //ctx->aes_ctx = (oaes_ctx*) oaes_alloc();
    size_t i, j;
	__m128i _a, _b, _c;
	uint64_t hi, lo;
	uint64_t *p = NULL;
	RDATA_ALIGN16 uint8_t expandedKey[240];
	
    VARIANT1_INIT();
    VARIANT2_INIT(ctx->b, ctx->state);
	if(hp_state == NULL)
		printf("Not");
		
    //oaes_key_import_data(ctx->aes_ctx, ctx->state.hs.b, AES_KEY_SIZE);
	// use aligned data
    //memcpy(expandedKey, ctx->aes_ctx->key->exp_data, ctx->aes_ctx->key->exp_data_len);
	
    /*for (i = 0; i < CN_INIT; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            aesni_pseudo_round(&ctx->text[AES_BLOCK_SIZE * j],
                    &ctx->text[AES_BLOCK_SIZE * j],
                    expandedKey);
        }
        memcpy(&hp_state[i * INIT_SIZE_BYTE], ctx->text, INIT_SIZE_BYTE);
    }*/
	
	aes_expand_key(ctx->state.hs.b, expandedKey);
	
        for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
        {
            aes_pseudo_round(ctx->text, ctx->text, expandedKey, INIT_SIZE_BLK);
			
            memcpy(&hp_state[i * INIT_SIZE_BYTE], ctx->text, INIT_SIZE_BYTE);
			
        }

    U64(ctx->a)[0] = U64(&ctx->state.k[0])[0] ^ U64(&ctx->state.k[32])[0];
    U64(ctx->a)[1] = U64(&ctx->state.k[0])[1] ^ U64(&ctx->state.k[32])[1];
    U64(ctx->b)[0] = U64(&ctx->state.k[16])[0] ^ U64(&ctx->state.k[48])[0];
    U64(ctx->b)[1] = U64(&ctx->state.k[16])[1] ^ U64(&ctx->state.k[48])[1];

	_b = _mm_load_si128(R128(ctx->b));

    for (i = 0; i < ITER_DIV; i++) {
        /* Dependency chain: address -> read value ------+
         * written value <-+ hard function (AES or MUL) <+
         * next address  <-+
         */
        /* Iteration 1 */
		//PreAES
		j = state_index(ctx->a); \
		_c = _mm_load_si128(R128(&hp_state[j])); \
		_a = _mm_load_si128(R128(ctx->a));
		//AES
		_c = _mm_aesenc_si128(_c, _a);
		//PostAES
		_mm_store_si128(R128(ctx->c), _c);
		_b = _mm_xor_si128(_b, _c);
		_mm_store_si128(R128(&hp_state[j]), _b);
		VARIANT1_1(&hp_state[j]);
		j = state_index(ctx->c);
		p = U64(&hp_state[j]);
		ctx->b[0] = p[0]; ctx->b[1] = p[1];
		__asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "%a" ((ctx->c)[0]), "rm" (ctx->b[0]) : "cc");
		ctx->a[0] += hi; ctx->a[1] += lo;
		p = U64(&hp_state[j]);
		p[0] = ctx->a[0];  p[1] = ctx->a[1];
		ctx->a[0] ^= ctx->b[0]; ctx->a[1] ^= ctx->b[1];
		VARIANT1_2(p + 1);
		_b = _c;
		
		/*
        j = e2i(ctx->a);
        //aesb_single_round(&hp_state[j * AES_BLOCK_SIZE], ctx->c, ctx->a);
        VARIANT2_SHUFFLE_ADD(hp_state, j * AES_BLOCK_SIZE, ctx->a, ctx->b);
        xor_blocks_dst(ctx->c, ctx->b, &hp_state[j * AES_BLOCK_SIZE]);
        VARIANT1_1((uint8_t*)&hp_state[j * AES_BLOCK_SIZE]);
        
        j = e2i(ctx->c);

        uint64_t* dst = (uint64_t*)&hp_state[j * AES_BLOCK_SIZE];

        uint64_t t[2];
        t[0] = dst[0];
        t[1] = dst[1];

        VARIANT2_INTEGER_MATH(t, ctx->c);

        uint64_t hi,lo;
		__asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "%a" (((uint64_t*)ctx->c)[0]), "rm" (t[0]) : "cc");

        VARIANT2_2();
        VARIANT2_SHUFFLE_ADD(hp_state, j * AES_BLOCK_SIZE, ctx->a, ctx->b);

        ((uint64_t*)ctx->a)[0] += hi;
        ((uint64_t*)ctx->a)[1] += lo;

        dst[0] = ((uint64_t*)ctx->a)[0];
        dst[1] = ((uint64_t*)ctx->a)[1];

        ((uint64_t*)ctx->a)[0] ^= t[0];
        ((uint64_t*)ctx->a)[1] ^= t[1];

        VARIANT1_2((uint8_t*)&hp_state[j * AES_BLOCK_SIZE]);
        copy_block(ctx->b + AES_BLOCK_SIZE, ctx->b);
        copy_block(ctx->b, ctx->c);*/
    }

    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    //oaes_key_import_data(ctx->aes_ctx, &ctx->state.hs.b[32], AES_KEY_SIZE);
	//memcpy(expandedKey, ctx->aes_ctx->key->exp_data, ctx->aes_ctx->key->exp_data_len);
    /*aes_expand_key(&ctx->state.hs.b[32], expandedKey);
	for (i = 0; i < CN_INIT; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            xor_blocks(&ctx->text[j * AES_BLOCK_SIZE],
                    &hp_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
            aesni_pseudo_round(&ctx->text[j * AES_BLOCK_SIZE],
                    &ctx->text[j * AES_BLOCK_SIZE],
                    expandedKey);
			aesni_pseudo_round_xor(&ctx->text[j * AES_BLOCK_SIZE],
					&ctx->text[j * AES_BLOCK_SIZE],
					expandedKey, &hp_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
        }
    }*/

	aes_expand_key(&ctx->state.hs.b[32], expandedKey);
        for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
        {
            // add the xor to the pseudo round
            aes_pseudo_round_xor(ctx->text, ctx->text, expandedKey, &hp_state[i * INIT_SIZE_BYTE], INIT_SIZE_BLK);
        }
		
    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);

    hash_permutation(&ctx->state.hs);

    /*memcpy(hash, &state, 32);*/
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);

    //oaes_free((OAES_CTX **) &ctx->aes_ctx);
}

void  cryptonightdarklite_fast_hash(const char* input, char* output, uint32_t len) {
    union hash_state state;
    hash_process(&state, (const uint8_t*) input, len);
    memcpy(output, &state, HASH_SIZE);
}

