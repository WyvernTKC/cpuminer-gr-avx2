#ifndef GR_GATE_H_
#define GR_GATE_H_

#include "algo-gate-api.h"
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/echo/sph_echo.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/nist.h"
#include "algo/skein/sph_skein.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "cryptonote/cryptonight.h"
#include "simd-utils.h"
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__AES__)
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#endif

#if defined(__AVX2__)
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/whirlpool/whirlpool-hash-4way.h"
#endif

#if defined(__VAES__)
#include "algo/echo/echo-hash-4way.h"
#include "algo/groestl/groestl512-hash-4way.h"
#endif

#define CN_4WAY 2
#define CN_2WAY 1

#if defined(__AVX2__) && defined(__AES__)
#define GR_4WAY 1
#endif

enum Algo {
  BLAKE = 0,         // 0
  BMW,               // 1
  GROESTL,           // 2
  JH,                // 3
  KECCAK,            // 4
  SKEIN,             // 5
  LUFFA,             // 6
  CUBEHASH,          // 7
  SHAVITE,           // 8
  SIMD,              // 9
  ECHO,              // 10
  HAMSI,             // 11
  FUGUE,             // 12
  SHABAL,            // 13
  WHIRLPOOL,         // 14
  CNDark,            // 15
  CNDarklite,        // 16
  CNFast,            // 17
  CNLite,            // 18
  CNTurtle,          // 19
  CNTurtlelite,      // 20
  GR_HASH_FUNC_COUNT // 21
};

enum CryptonightConfig { Turtlelite = 0, Turtle, Darklite, Dark, Lite, Fast };

// Only 3 CN algos are selected from available 6.
extern __thread uint8_t gr_hash_order[GR_HASH_FUNC_COUNT - 3 + 1];

void gr_getAlgoString(const uint8_t *block, uint8_t *selectedAlgoOutput);

#if defined(GR_4WAY)

union _gr_4way_context_overlay {
  blake512_4way_context blake;
  bmw512_4way_context bmw;
#if defined(__VAES__)
  groestl512_2way_context groestl;
  echo_2way_context echo;
#else
  hashState_groestl groestl;
  hashState_echo echo;
#endif
  shavite512_2way_context shavite;
  skein512_4way_context skein;
  jh512_4way_context jh;
  keccak512_4way_context keccak;
  luffa_2way_context luffa;
  cube_2way_context cube;
  simd_2way_context simd;
  hamsi512_4way_context hamsi;
  hashState_fugue fugue;
  shabal512_4way_context shabal;
  whirlpool_4way_context whirlpool;
} __attribute__((aligned(64)));

typedef union _gr_4way_context_overlay gr_4way_context_overlay;

extern __thread gr_4way_context_overlay gr_4way_ctx;

int gr_4way_hash(void *hash, const void *input, const int thrid);
int scanhash_gr_4way(struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr);

#endif // GR_4WAY

union _gr_context_overlay {
#if defined(__AES__)
  hashState_echo echo;
  hashState_groestl groestl;
  hashState_fugue fugue;
#else
  sph_groestl512_context groestl;
  sph_echo512_context echo;
  sph_fugue512_context fugue;
#endif
  sph_blake512_context blake;
  sph_bmw512_context bmw;
  sph_skein512_context skein;
  sph_jh512_context jh;
  sph_keccak512_context keccak;
  hashState_luffa luffa;
  cubehashParam cube;
  shavite512_context shavite;
  hashState_sd simd;
  sph_hamsi512_context hamsi;
  sph_shabal512_context shabal;
  sph_whirlpool_context whirlpool;
} __attribute__((aligned(64)));

typedef union _gr_context_overlay gr_context_overlay;

extern __thread gr_context_overlay gr_ctx;

int gr_hash(void *hash, const void *input0, const void *input1,
            const int thrid);
int scanhash_gr(struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                struct thr_info *mythr);

// Memory state
extern __thread uint8_t *hp_state;

// Time ratio for each kind of block/rotation.
// Data gathered from 5 days of mining.
static const double time_ratio[20] = {
    0.094555300, 0.055475289, 0.021255548, 0.022460854, 0.128275216,
    0.044809767, 0.063186119, 0.037458185, 0.035620290, 0.010150077,
    0.111971052, 0.051200750, 0.058180067, 0.044812371, 0.029148607,
    0.009918388, 0.074939800, 0.058862119, 0.032738490, 0.014981712};

// Data gathered from 16 days of mining, 18251 blocks.
// This data used incorrect block types / cryptonight variants.
static const double time_ratio_old[20] = {
    0.081253, 0.077720, 0.048476, 0.046917, 0.077396, 0.044738, 0.048130,
    0.046897, 0.046318, 0.027358, 0.080602, 0.048928, 0.048283, 0.048863,
    0.044444, 0.027389, 0.048813, 0.050674, 0.028581, 0.028219};

static const double gr_benchmark_time = 450000000;

// Values for 20 CN rotations.
static const uint8_t cn[20][3] = {
    {0, 1, 2}, {0, 1, 3}, {0, 1, 4}, {0, 1, 5}, {0, 2, 3},  // 05
    {0, 2, 4}, {0, 2, 5}, {0, 3, 4}, {0, 3, 5}, {0, 4, 5},  // 10
    {1, 2, 3}, {1, 2, 4}, {1, 2, 5}, {1, 3, 4}, {1, 3, 5},  // 15
    {1, 4, 5}, {2, 3, 4}, {2, 3, 5}, {2, 4, 5}, {3, 4, 5}}; // 20

// Uses hp_state as memory.
void AllocateNeededMemory(bool max);

void select_tuned_config();
void tune(void *input, int thr_id);

void benchmark(void *input, int thr_id, long sleep_time);

bool register_gr_algo(algo_gate_t *gate);

#endif // GR_GATE_H_
