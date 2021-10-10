/*
 * Copyright 2021 Delgon
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "gr-gate.h"

#if defined(GR_4WAY)

#include "cryptonote/cryptonight.h"

#define CRYPTONIGHT_HASH(variant, way)                                         \
  if (vectorized) {                                                            \
    dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);                       \
  }                                                                            \
  if (prefetch_l1) {                                                           \
    if (way == CN_4WAY) {                                                      \
      cryptonight_4way_hash<variant, true>(hash0, hash1, hash2, hash3, hash0,  \
                                           hash1, hash2, hash3);               \
    } else if (way == CN_2WAY) {                                               \
      cryptonight_2way_hash<variant, true>(hash0, hash1, hash0, hash1);        \
      cryptonight_2way_hash<variant, true>(hash2, hash3, hash2, hash3);        \
    } else {                                                                   \
      cryptonight_hash<variant, true>(hash0, hash0);                           \
      cryptonight_hash<variant, true>(hash1, hash1);                           \
      cryptonight_hash<variant, true>(hash2, hash2);                           \
      cryptonight_hash<variant, true>(hash3, hash3);                           \
    }                                                                          \
  } else {                                                                     \
    if (way == CN_4WAY) {                                                      \
      cryptonight_4way_hash<variant, false>(hash0, hash1, hash2, hash3, hash0, \
                                            hash1, hash2, hash3);              \
    } else if (way == CN_2WAY) {                                               \
      cryptonight_2way_hash<variant, false>(hash0, hash1, hash0, hash1);       \
      cryptonight_2way_hash<variant, false>(hash2, hash3, hash2, hash3);       \
    } else {                                                                   \
      cryptonight_hash<variant, false>(hash0, hash0);                          \
      cryptonight_hash<variant, false>(hash1, hash1);                          \
      cryptonight_hash<variant, false>(hash2, hash2);                          \
      cryptonight_hash<variant, false>(hash3, hash3);                          \
    }                                                                          \
  }                                                                            \
  vectorized = false;

int gr_4way_hash(void *output, const void *input, const int thr_id) {
  uint64_t vhash[10 * 4] __attribute__((aligned(128)));
  uint64_t vhashA[10 * 2] __attribute__((aligned(128)));
  uint64_t vhashB[10 * 2] __attribute__((aligned(128)));
  uint64_t hash0[10] __attribute__((aligned(64)));
  uint64_t hash1[10] __attribute__((aligned(64)));
  uint64_t hash2[10] __attribute__((aligned(64)));
  uint64_t hash3[10] __attribute__((aligned(64)));

  gr_4way_context_overlay ctx;
  memcpy(&ctx, &gr_4way_ctx, sizeof(ctx));
  // Start as vectorized from input.
  bool vectorized = true;

  switch (gr_hash_order[0]) {
  case BLAKE:
    blake512_4way_full(&ctx.blake, vhash, input, 80);
    vectorized = true;
    break;
  case BMW:
    bmw512_4way_init(&ctx.bmw);
    bmw512_4way_update(&ctx.bmw, input, 80);
    bmw512_4way_close(&ctx.bmw, vhash);
    vectorized = true;
    break;
  case GROESTL:
#if defined(__VAES__)
    rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
    groestl512_2way_full(&ctx.groestl, vhashA, vhashA, 80);
    groestl512_2way_full(&ctx.groestl, vhashB, vhashB, 80);
    rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
    vectorized = true;
#else
    dintrlv_4x64(hash0, hash1, hash2, hash3, input, 640);
    groestl512_full(&ctx.groestl, hash0, hash0, 640);
    groestl512_full(&ctx.groestl, hash1, hash1, 640);
    groestl512_full(&ctx.groestl, hash2, hash2, 640);
    groestl512_full(&ctx.groestl, hash3, hash3, 640);
    vectorized = false;
#endif
    break;
  case SKEIN:
    skein512_4way_full(&ctx.skein, vhash, input, 80);
    vectorized = true;
    break;
  case JH:
    jh512_4way_init(&ctx.jh);
    jh512_4way_update(&ctx.jh, input, 80);
    jh512_4way_close(&ctx.jh, vhash);
    vectorized = true;
    break;
  case KECCAK:
    keccak512_4way_init(&ctx.keccak);
    keccak512_4way_update(&ctx.keccak, input, 80);
    keccak512_4way_close(&ctx.keccak, vhash);
    vectorized = true;
    break;
  case LUFFA:
    rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
    luffa512_2way_full(&ctx.luffa, vhashA, vhashA, 80);
    luffa512_2way_full(&ctx.luffa, vhashB, vhashB, 80);
    rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
    vectorized = true;
    break;
  case CUBEHASH:
    rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
    cube_2way_full(&ctx.cube, vhashA, 512, vhashA, 80);
    cube_2way_full(&ctx.cube, vhashB, 512, vhashB, 80);
    rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
    vectorized = true;
    break;
  case SHAVITE:
    rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
    shavite512_2way_full(&ctx.shavite, vhashA, vhashA, 80);
    shavite512_2way_full(&ctx.shavite, vhashB, vhashB, 80);
    rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
    vectorized = true;
    break;
  case SIMD:
    rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
    simd512_2way_full(&ctx.simd, vhashA, vhashA, 80);
    simd512_2way_full(&ctx.simd, vhashB, vhashB, 80);
    rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
    vectorized = true;
    break;
  case ECHO:
#if defined(__VAES__)
    rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
    echo_2way_full(&ctx.echo, vhashA, 512, vhashA, 80);
    echo_2way_full(&ctx.echo, vhashB, 512, vhashB, 80);
    rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
    vectorized = true;
#else
    dintrlv_4x64(hash0, hash1, hash2, hash3, input, 640);
    echo_full(&ctx.echo, (BitSequence *)hash0, 512, (const BitSequence *)hash0,
              80);
    echo_full(&ctx.echo, (BitSequence *)hash1, 512, (const BitSequence *)hash1,
              80);
    echo_full(&ctx.echo, (BitSequence *)hash2, 512, (const BitSequence *)hash2,
              80);
    echo_full(&ctx.echo, (BitSequence *)hash3, 512, (const BitSequence *)hash3,
              80);
    vectorized = false;
#endif
    break;
  case HAMSI:
    hamsi512_4way_init(&ctx.hamsi);
    hamsi512_4way_update(&ctx.hamsi, input, 80);
    hamsi512_4way_close(&ctx.hamsi, vhash);
    vectorized = true;
    break;
  case FUGUE:
    dintrlv_4x64(hash0, hash1, hash2, hash3, input, 640);
    fugue512_full(&ctx.fugue, hash0, hash0, 80);
    fugue512_full(&ctx.fugue, hash1, hash1, 80);
    fugue512_full(&ctx.fugue, hash2, hash2, 80);
    fugue512_full(&ctx.fugue, hash3, hash3, 80);
    vectorized = false;
    break;
  case SHABAL:
    shabal512_4way_init(&ctx.shabal);
    rintrlv_4x64_4x32(vhash, input, 640);
    shabal512_4way_update(&ctx.shabal, vhash, 80);
    shabal512_4way_close(&ctx.shabal, vhash);
    dintrlv_4x32_512(hash0, hash1, hash2, hash3, vhash);
    vectorized = false;
    break;
  case WHIRLPOOL:
    whirlpool_4way_init(&ctx.whirlpool);
    whirlpool_4way(&ctx.whirlpool, input, 80);
    whirlpool_4way_close(&ctx.whirlpool, vhash);
    vectorized = true;
    break;
  }

  for (int i = 1; i < 15 + 3; i++) {
    const uint8_t algo = gr_hash_order[i];
    switch (algo) {
    case BLAKE:
      if (!vectorized) {
        intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
      }
      blake512_4way_full(&ctx.blake, vhash, vhash, 64);
      vectorized = true;
      break;
    case BMW:
      bmw512_4way_init(&ctx.bmw);
      if (!vectorized) {
        intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
      }
      bmw512_4way_update(&ctx.bmw, vhash, 64);
      bmw512_4way_close(&ctx.bmw, vhash);
      vectorized = true;
      break;
    case GROESTL:
#if defined(__VAES__)
      if (vectorized) {
        rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
      } else {
        intrlv_2x128_512(vhashA, hash0, hash1);
        intrlv_2x128_512(vhashB, hash2, hash3);
      }
      groestl512_2way_full(&ctx.groestl, vhashA, vhashA, 64);
      groestl512_2way_full(&ctx.groestl, vhashB, vhashB, 64);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
#else
      if (vectorized) {
        dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
      }
      groestl512_full(&ctx.groestl, hash0, hash0, 512);
      groestl512_full(&ctx.groestl, hash1, hash1, 512);
      groestl512_full(&ctx.groestl, hash2, hash2, 512);
      groestl512_full(&ctx.groestl, hash3, hash3, 512);
      vectorized = false;
#endif
      break;
    case SKEIN:
      if (!vectorized) {
        intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
      }
      skein512_4way_full(&ctx.skein, vhash, vhash, 64);
      vectorized = true;
      break;
    case JH:
      jh512_4way_init(&ctx.jh);
      if (!vectorized) {
        intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
      }
      jh512_4way_update(&ctx.jh, vhash, 64);
      jh512_4way_close(&ctx.jh, vhash);
      vectorized = true;
      break;
    case KECCAK:
      keccak512_4way_init(&ctx.keccak);
      if (!vectorized) {
        intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
      }
      keccak512_4way_update(&ctx.keccak, vhash, 64);
      keccak512_4way_close(&ctx.keccak, vhash);
      vectorized = true;
      break;
    case LUFFA:
      if (vectorized) {
        rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
      } else {
        intrlv_2x128_512(vhashA, hash0, hash1);
        intrlv_2x128_512(vhashB, hash2, hash3);
      }
      luffa512_2way_full(&ctx.luffa, vhashA, vhashA, 64);
      luffa512_2way_full(&ctx.luffa, vhashB, vhashB, 64);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case CUBEHASH:
      if (vectorized) {
        rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
      } else {
        intrlv_2x128_512(vhashA, hash0, hash1);
        intrlv_2x128_512(vhashB, hash2, hash3);
      }
      cube_2way_full(&ctx.cube, vhashA, 512, vhashA, 64);
      cube_2way_full(&ctx.cube, vhashB, 512, vhashB, 64);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case SHAVITE:
      if (vectorized) {
        rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
      } else {
        intrlv_2x128_512(vhashA, hash0, hash1);
        intrlv_2x128_512(vhashB, hash2, hash3);
      }
      shavite512_2way_full(&ctx.shavite, vhashA, vhashA, 64);
      shavite512_2way_full(&ctx.shavite, vhashB, vhashB, 64);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case SIMD:
      if (vectorized) {
        rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
      } else {
        intrlv_2x128_512(vhashA, hash0, hash1);
        intrlv_2x128_512(vhashB, hash2, hash3);
      }
      simd512_2way_full(&ctx.simd, vhashA, vhashA, 64);
      simd512_2way_full(&ctx.simd, vhashB, vhashB, 64);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case ECHO:
#if defined(__VAES__)
      if (vectorized) {
        rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
      } else {
        intrlv_2x128_512(vhashA, hash0, hash1);
        intrlv_2x128_512(vhashB, hash2, hash3);
      }
      echo_2way_full(&ctx.echo, vhashA, 512, vhashA, 64);
      echo_2way_full(&ctx.echo, vhashB, 512, vhashB, 64);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
#else
      if (vectorized) {
        dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
      }
      echo_full(&ctx.echo, (BitSequence *)hash0, 512,
                (const BitSequence *)hash0, 64);
      echo_full(&ctx.echo, (BitSequence *)hash1, 512,
                (const BitSequence *)hash1, 64);
      echo_full(&ctx.echo, (BitSequence *)hash2, 512,
                (const BitSequence *)hash2, 64);
      echo_full(&ctx.echo, (BitSequence *)hash3, 512,
                (const BitSequence *)hash3, 64);
      vectorized = false;
#endif
      break;
    case HAMSI:
      hamsi512_4way_init(&ctx.hamsi);
      if (!vectorized) {
        intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
      }
      hamsi512_4way_update(&ctx.hamsi, vhash, 64);
      hamsi512_4way_close(&ctx.hamsi, vhash);
      vectorized = true;
      break;
    case FUGUE:
      if (vectorized) {
        dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
      }
      fugue512_full(&ctx.fugue, hash0, hash0, 64);
      fugue512_full(&ctx.fugue, hash1, hash1, 64);
      fugue512_full(&ctx.fugue, hash2, hash2, 64);
      fugue512_full(&ctx.fugue, hash3, hash3, 64);
      vectorized = false;
      break;
    case SHABAL:
      shabal512_4way_init(&ctx.shabal);
      if (vectorized) {
        dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
      }
      intrlv_4x32_512(vhash, hash0, hash1, hash2, hash3);
      shabal512_4way_update(&ctx.shabal, vhash, 64);
      shabal512_4way_close(&ctx.shabal, vhash);
      dintrlv_4x32_512(hash0, hash1, hash2, hash3, vhash);
      vectorized = false;
      break;
    case WHIRLPOOL:
      whirlpool_4way_init(&ctx.whirlpool);
      if (!vectorized) {
        intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
      }
      whirlpool_4way(&ctx.whirlpool, vhash, 64);
      whirlpool_4way_close(&ctx.whirlpool, vhash);
      vectorized = true;
      break;
    case CNTurtlelite:
      CRYPTONIGHT_HASH(TURTLELITE, cn_config[Turtlelite]);
      break;
    case CNTurtle:
      CRYPTONIGHT_HASH(TURTLE, cn_config[Turtle]);
      break;
    case CNDarklite:
      CRYPTONIGHT_HASH(DARKLITE, cn_config[Darklite]);
      break;
    case CNDark:
      CRYPTONIGHT_HASH(DARK, cn_config[Dark]);
      break;
    case CNLite:
      CRYPTONIGHT_HASH(LITE, cn_config[Lite]);
      break;
    case CNFast:
      CRYPTONIGHT_HASH(FAST, cn_config[Fast]);
      break;
    }

    // Stop early. do not stop while benchmarking or tuning.
    if (work_restart[thr_id].restart && !(opt_benchmark || opt_tune)) {
      if (opt_debug && !thr_id) {
        applog(LOG_DEBUG, "Threads exit early.");
      }
      return 0;
    }
  }

  // This should not happen as CN should be last algorithm.
  if (vectorized) {
    dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
  }
  memcpy(output, hash0, 32);
  memcpy(&((uint8_t *)output)[32], hash1, 32);
  memcpy(&((uint8_t *)output)[64], hash2, 32);
  memcpy(&((uint8_t *)output)[96], hash3, 32);

  return 1;
}

int scanhash_gr_4way(struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr) {
  uint32_t hash[8 * 4] __attribute__((aligned(64)));
  uint32_t vdata[20 * 4] __attribute__((aligned(64)));
  uint32_t edata[20] __attribute__((aligned(64)));
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  const uint32_t first_nonce = pdata[19];
  const uint32_t last_nonce = max_nonce - 4;
  const int thr_id = mythr->id;
  uint32_t n = first_nonce;
  uint32_t hashes = 1;
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  volatile uint8_t *restart = &(work_restart[thr_id].restart);

  if (!opt_tuned && opt_tune) {
    sleep(1);
    tune(pdata, thr_id);
    opt_tuned = true; // Tuned.
    opt_tune = false;
    return 0;
  }

  if (opt_benchmark) {
    sleep(1);
    if (thr_id == 0) {
      applog(LOG_BLUE, "Starting benchmark. Benchmark takes %.0lfs to complete",
             gr_benchmark_time / 1e6);
    }
    benchmark(pdata, thr_id, 0);
#ifdef __MINGW32__
    // Make it sleep for some time. Some Windows configuration run the miner
    // in separate window that closes after it finishes and it is not possible
    // to get benchmark results.
    sleep(300);
#endif
    if (thr_id == 0) {
      exit(0);
    }
  }

  mm256_bswap32_intrlv80_4x64(vdata, pdata);

  // Check if algorithm order changed.
  mm128_bswap32_80(edata, pdata);
  gr_getAlgoString((const uint8_t *)(&edata[1]), gr_hash_order);
  if (opt_debug && !thr_id) {
    char order[100];
    for (int i = 0; i < 15 + 3; i++) {
      sprintf(order + (i * 3), "%02d ", gr_hash_order[i]);
    }
    applog(LOG_DEBUG, "Hash order %s", order);
  }
  if (opt_tuned) {
    select_tuned_config(thr_id);
  }

  // Allocates hp_state for Cryptonight algorithms.
  // Needs to be run AFTER gr_hash_order is set!
  AllocateNeededMemory(true);

  *noncev = mm256_intrlv_blend_32(
      _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);

  if (!is_thread_used(thr_id)) {
    while (!(*restart)) {
      // sleep for 50ms
      // TODO
      // use pthread_cond instead.
      usleep(50000);
    }
    return 0;
  }

  while (likely((n < last_nonce) && !(*restart))) {
    if (gr_4way_hash(hash, vdata, thr_id)) {
      if (hashes % 50 != 0) {
        for (int i = 0; i < 4; i++) {
          if (unlikely(valid_hash(hash + (i << 3), ptarget))) {
            if (opt_debug) {
              applog(LOG_BLUE, "Solution found. Nonce: %u | Diff: %.10lf",
                     bswap_32(n + i), hash_to_diff(hash + (i << 3)));
            }
            pdata[19] = bswap_32(n + i);
            submit_solution(work, hash + (i << 3), mythr);
            check_prepared();
          }
        }
      }
    }
    *noncev = _mm256_add_epi32(*noncev, m256_const1_64(0x0000000400000000));
    n += 4;
    hashes += (enable_donation && donation_percent >= 1.75) ? 0 : 1;
  }
  pdata[19] = n;
  *hashes_done = n - first_nonce;
  return 0;
}

#endif // GR_4WAY
