/*
 * Copyright 2021 Delgon
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "gr-gate.h"

#include "cryptonote/cryptonight.h"

#define CRYPTONIGHT_HASH(variant, way)                                         \
  if (prefetch_l1) {                                                           \
    if (way == CN_2WAY) {                                                      \
      cryptonight_2way_hash<variant, true>(hash0, hash1, hash0, hash1);        \
    } else {                                                                   \
      cryptonight_hash<variant, true>(hash0, hash0);                           \
      cryptonight_hash<variant, true>(hash1, hash1);                           \
    }                                                                          \
  } else {                                                                     \
    if (way == CN_2WAY) {                                                      \
      cryptonight_2way_hash<variant, false>(hash0, hash1, hash0, hash1);       \
    } else {                                                                   \
      cryptonight_hash<variant, false>(hash0, hash0);                          \
      cryptonight_hash<variant, false>(hash1, hash1);                          \
    }                                                                          \
  }

#define CORE_HASH(hash, input, output, size)                                   \
  sph_##hash##512_init(&ctx.hash);                                             \
  sph_##hash##512(&ctx.hash, input, size);                                     \
  sph_##hash##512_close(&ctx.hash, output);

int gr_hash(void *output, const void *input0, const void *input1,
            const int thr_id) {
  uint64_t hash0[10] __attribute__((aligned(64)));
  uint64_t hash1[10] __attribute__((aligned(64)));
  gr_context_overlay ctx;
  memcpy(&ctx, &gr_ctx, sizeof(ctx));

  switch (gr_hash_order[0]) {
  case BLAKE:
    CORE_HASH(blake, input0, hash0, 80);
    CORE_HASH(blake, input1, hash1, 80);
    break;
  case BMW:
    CORE_HASH(bmw, input0, hash0, 80);
    CORE_HASH(bmw, input1, hash1, 80);
    break;
  case GROESTL:
#if defined(__AES__)
    groestl512_full(&ctx.groestl, (char *)hash0, (char *)input0, 640);
    groestl512_full(&ctx.groestl, (char *)hash1, (char *)input1, 640);
#else
    CORE_HASH(groestl, input0, hash0, 80);
    CORE_HASH(groestl, input1, hash1, 80);
#endif
    break;
  case SKEIN:
    CORE_HASH(skein, input0, hash0, 80);
    CORE_HASH(skein, input1, hash1, 80);
    break;
  case JH:
    CORE_HASH(jh, input0, hash0, 80);
    CORE_HASH(jh, input1, hash1, 80);
    break;
  case KECCAK:
    CORE_HASH(keccak, input0, hash0, 80);
    CORE_HASH(keccak, input1, hash1, 80);
    break;
  case LUFFA:
    luffa_full(&ctx.luffa, (BitSequence *)hash0, 512,
               (const BitSequence *)input0, 80);
    luffa_full(&ctx.luffa, (BitSequence *)hash1, 512,
               (const BitSequence *)input1, 80);
    break;
  case CUBEHASH:
    cubehash_full(&ctx.cube, (byte *)hash0, 512, (byte *)input0, 80);
    cubehash_full(&ctx.cube, (byte *)hash1, 512, (byte *)input1, 80);
    break;
  case SHAVITE:
    shavite512_full(&ctx.shavite, hash0, input0, 80);
    shavite512_full(&ctx.shavite, hash1, input1, 80);
    break;
  case SIMD:
    simd_full(&ctx.simd, (BitSequence *)hash0, (const BitSequence *)input0,
              640);
    simd_full(&ctx.simd, (BitSequence *)hash1, (const BitSequence *)input1,
              640);
    break;
  case ECHO:
#if defined(__AES__)
    echo_full(&ctx.echo, (BitSequence *)hash0, 512, (const BitSequence *)input0,
              80);
    echo_full(&ctx.echo, (BitSequence *)hash1, 512, (const BitSequence *)input1,
              80);
#else
    CORE_HASH(echo, input0, hash0, 80);
    CORE_HASH(echo, input1, hash1, 80);
#endif
    break;
  case HAMSI:
    CORE_HASH(hamsi, input0, hash0, 80);
    CORE_HASH(hamsi, input1, hash1, 80);
    break;
  case FUGUE:
#if defined(__AES__)
    fugue512_full(&ctx.fugue, hash0, input0, 80);
    fugue512_full(&ctx.fugue, hash1, input1, 80);
#else
    sph_fugue512_full(&ctx.fugue, hash0, input0, 80);
    sph_fugue512_full(&ctx.fugue, hash1, input1, 80);
#endif
    break;
  case SHABAL:
    CORE_HASH(shabal, input0, hash0, 80);
    CORE_HASH(shabal, input1, hash1, 80);
    break;
  case WHIRLPOOL:
    sph_whirlpool512_full(&ctx.whirlpool, hash0, input0, 80);
    sph_whirlpool512_full(&ctx.whirlpool, hash1, input1, 80);
    break;
  }

  for (int i = 1; i < 15 + 3; i++) {
    const uint8_t algo = gr_hash_order[i];
    switch (algo) {
    case BLAKE:
      CORE_HASH(blake, hash0, hash0, 64);
      CORE_HASH(blake, hash1, hash1, 64);
      break;
    case BMW:
      CORE_HASH(bmw, hash0, hash0, 64);
      CORE_HASH(bmw, hash1, hash1, 64);
      break;
    case GROESTL:
#if defined(__AES__)
      groestl512_full(&ctx.groestl, (char *)hash0, (char *)hash0, 512);
      groestl512_full(&ctx.groestl, (char *)hash1, (char *)hash1, 512);
#else
      CORE_HASH(groestl, hash0, hash0, 64);
      CORE_HASH(groestl, hash1, hash1, 64);
#endif
      break;
    case SKEIN:
      CORE_HASH(skein, hash0, hash0, 64);
      CORE_HASH(skein, hash1, hash1, 64);
      break;
    case JH:
      CORE_HASH(jh, hash0, hash0, 64);
      CORE_HASH(jh, hash1, hash1, 64);
      break;
    case KECCAK:
      CORE_HASH(keccak, hash0, hash0, 64);
      CORE_HASH(keccak, hash1, hash1, 64);
      break;
    case LUFFA:
      luffa_full(&ctx.luffa, (BitSequence *)hash0, 512,
                 (const BitSequence *)hash0, 64);
      luffa_full(&ctx.luffa, (BitSequence *)hash1, 512,
                 (const BitSequence *)hash1, 64);
      break;
    case CUBEHASH:
      cubehash_full(&ctx.cube, (byte *)hash0, 512, (byte *)hash0, 64);
      cubehash_full(&ctx.cube, (byte *)hash1, 512, (byte *)hash1, 64);
      break;
    case SHAVITE:
      shavite512_full(&ctx.shavite, hash0, hash0, 64);
      shavite512_full(&ctx.shavite, hash1, hash1, 64);
      break;
    case SIMD:
      simd_full(&ctx.simd, (BitSequence *)hash0, (const BitSequence *)hash0,
                512);
      simd_full(&ctx.simd, (BitSequence *)hash1, (const BitSequence *)hash1,
                512);
      break;
    case ECHO:
#if defined(__AES__)
      echo_full(&ctx.echo, (BitSequence *)hash0, 512,
                (const BitSequence *)hash0, 64);
      echo_full(&ctx.echo, (BitSequence *)hash1, 512,
                (const BitSequence *)hash1, 64);
#else
      CORE_HASH(echo, hash0, hash0, 64);
      CORE_HASH(echo, hash1, hash1, 64);
#endif
      break;
    case HAMSI:
      CORE_HASH(hamsi, hash0, hash0, 64);
      CORE_HASH(hamsi, hash1, hash1, 64);
      break;
    case FUGUE:
#if defined(__AES__)
      fugue512_full(&ctx.fugue, hash0, hash0, 64);
      fugue512_full(&ctx.fugue, hash1, hash1, 64);
#else
      sph_fugue512_full(&ctx.fugue, hash0, hash0, 64);
      sph_fugue512_full(&ctx.fugue, hash1, hash1, 64);
#endif
      break;
    case SHABAL:
      CORE_HASH(shabal, hash0, hash0, 64);
      CORE_HASH(shabal, hash1, hash1, 64);
      break;
    case WHIRLPOOL:
      sph_whirlpool512_full(&ctx.whirlpool, hash0, hash0, 64);
      sph_whirlpool512_full(&ctx.whirlpool, hash1, hash1, 64);
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

    // Stop early.
    if (work_restart[thr_id].restart && !(opt_benchmark || opt_tune)) {
      if (opt_debug && !thr_id) {
        applog(LOG_DEBUG, "Threads exit early.");
      }
      return 0;
    }
  }
  memcpy(output, hash0, 32);
  memcpy(&((uint8_t *)output)[32], hash1, 32);
  return 1;
}

int scanhash_gr(struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                struct thr_info *mythr) {
  uint32_t hash[2 * 8] __attribute__((aligned(64)));
  uint32_t edata0[20] __attribute__((aligned(64)));
  uint32_t edata1[20] __attribute__((aligned(64)));
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  const uint32_t first_nonce = pdata[19];
  const uint32_t last_nonce = max_nonce - 2;
  const int thr_id = mythr->id;
  uint32_t nonce = first_nonce;
  uint32_t hashes = 1;
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

  mm128_bswap32_80(edata0, pdata);
  mm128_bswap32_80(edata1, pdata);

  gr_getAlgoString((const uint8_t *)(&edata0[1]), gr_hash_order);
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

  edata0[19] = nonce;
  edata1[19] = nonce + 1;

  if (!is_thread_used(thr_id)) {
    while (!(*restart)) {
      // sleep for 50ms
      // TODO
      // use pthread_cond instead.
      usleep(50000);
    }
    return 0;
  }
  while (likely((nonce < last_nonce) && !(*restart))) {
    if (gr_hash(hash, edata0, edata1, thr_id)) {
      if (hashes % 50 != 0) {
        for (int i = 0; i < 2; i++) {
          if (unlikely(valid_hash(hash + (i << 3), ptarget))) {
            if (opt_debug) {
              applog(LOG_BLUE, "Solution found. Nonce: %u | Diff: %.10lf",
                     bswap_32(nonce + i), hash_to_diff(hash + (i << 3)));
            }
            pdata[19] = bswap_32(nonce + i);
            submit_solution(work, hash + (i << 3), mythr);
            check_prepared();
          }
        }
      }
    }
    edata0[19] += 2;
    edata1[19] += 2;
    nonce += 2;
    hashes += (enable_donation && donation_percent >= 1.75) ? 0 : 1;
  }
  pdata[19] = nonce;
  *hashes_done = pdata[19] - first_nonce;
  return 0;
}
