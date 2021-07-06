#include "gr-gate.h"

#if defined(GR_4WAY)

#define CRYPTONIGHT_HASH(variant, way)                                         \
  if (vectorized) {                                                            \
    dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);                       \
  }                                                                            \
                                                                               \
  if (way == CN_4WAY) {                                                        \
    cryptonight_##variant##_4way_hash(hash0, hash1, hash2, hash3, hash0,       \
                                      hash1, hash2, hash3);                    \
  } else if (way == CN_2WAY) {                                                 \
    cryptonight_##variant##_2way_hash(hash0, hash1, hash0, hash1);             \
    cryptonight_##variant##_2way_hash(hash2, hash3, hash2, hash3);             \
  } else {                                                                     \
    cryptonight_##variant##_hash(hash0, hash0);                                \
    cryptonight_##variant##_hash(hash1, hash1);                                \
    cryptonight_##variant##_hash(hash2, hash2);                                \
    cryptonight_##variant##_hash(hash3, hash3);                                \
  }                                                                            \
  vectorized = false;

int gr_4way_hash(void *output, const void *input, int thrid) {
  uint64_t vhash[10 * 4] __attribute__((aligned(128)));
  uint64_t vhashA[10 * 2] __attribute__((aligned(128)));
  uint64_t vhashB[10 * 2] __attribute__((aligned(128)));
  uint64_t hash0[10] __attribute__((aligned(64)));
  uint64_t hash1[10] __attribute__((aligned(64)));
  uint64_t hash2[10] __attribute__((aligned(64)));
  uint64_t hash3[10] __attribute__((aligned(64)));

  gr_4way_context_overlay ctx;
  memcpy(&ctx, &gr_4way_ctx, sizeof(ctx));
  int size = 80;
  // Start as vectorized from input.
  bool vectorized = true;

  for (int i = 0; i < 15 + 3; i++) {
    const uint8_t algo = gr_hash_order[i];
    switch (algo) {
    case BLAKE:
      if (i == 0) {
        blake512_4way_full(&ctx.blake, vhash, input, size);
      } else {
        if (!vectorized) {
          intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
        }
        blake512_4way_full(&ctx.blake, vhash, vhash, size);
      }
      vectorized = true;
      break;
    case BMW:
      bmw512_4way_init(&ctx.bmw);
      if (i == 0) {
        bmw512_4way_update(&ctx.bmw, input, size);
      } else {
        if (!vectorized) {
          intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
        }
        bmw512_4way_update(&ctx.bmw, vhash, size);
      }
      bmw512_4way_close(&ctx.bmw, vhash);
      vectorized = true;
      break;
    case GROESTL:
#if defined(__VAES__)
      if (i == 0) {
        rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
      } else {
        if (vectorized) {
          rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
        } else {
          intrlv_2x128_512(vhashA, hash0, hash1);
          intrlv_2x128_512(vhashB, hash2, hash3);
        }
      }
      groestl512_2way_full(&ctx.groestl, vhashA, vhashA, size);
      groestl512_2way_full(&ctx.groestl, vhashB, vhashB, size);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
#else
      if (i == 0) {
        dintrlv_4x64(hash0, hash1, hash2, hash3, input, 640);
      } else {
        if (vectorized) {
          dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
        }
      }
      groestl512_full(&ctx.groestl, hash0, hash0, size << 3);
      groestl512_full(&ctx.groestl, hash1, hash1, size << 3);
      groestl512_full(&ctx.groestl, hash2, hash2, size << 3);
      groestl512_full(&ctx.groestl, hash3, hash3, size << 3);
      vectorized = false;
#endif
      break;
    case SKEIN:
      if (i == 0) {
        skein512_4way_full(&ctx.skein, vhash, input, size);
      } else {
        if (!vectorized) {
          intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
        }
        skein512_4way_full(&ctx.skein, vhash, vhash, size);
      }
      vectorized = true;
      break;
    case JH:
      jh512_4way_init(&ctx.jh);
      if (i == 0) {
        jh512_4way_update(&ctx.jh, input, size);
      } else {
        if (!vectorized) {
          intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
        }
        jh512_4way_update(&ctx.jh, vhash, size);
      }
      jh512_4way_close(&ctx.jh, vhash);
      vectorized = true;
      break;
    case KECCAK:
      keccak512_4way_init(&ctx.keccak);
      if (i == 0) {
        keccak512_4way_update(&ctx.keccak, input, size);
      } else {
        if (!vectorized) {
          intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
        }
        keccak512_4way_update(&ctx.keccak, vhash, size);
      }
      keccak512_4way_close(&ctx.keccak, vhash);
      vectorized = true;
      break;
    case LUFFA:
      if (i == 0) {
        rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
      } else {
        if (vectorized) {
          rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
        } else {
          intrlv_2x128_512(vhashA, hash0, hash1);
          intrlv_2x128_512(vhashB, hash2, hash3);
        }
      }
      luffa512_2way_full(&ctx.luffa, vhashA, vhashA, size);
      luffa512_2way_full(&ctx.luffa, vhashB, vhashB, size);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case CUBEHASH:
      if (i == 0) {
        rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
      } else {
        if (vectorized) {
          rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
        } else {
          intrlv_2x128_512(vhashA, hash0, hash1);
          intrlv_2x128_512(vhashB, hash2, hash3);
        }
      }
      cube_2way_full(&ctx.cube, vhashA, 512, vhashA, size);
      cube_2way_full(&ctx.cube, vhashB, 512, vhashB, size);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case SHAVITE:
      if (i == 0) {
        rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
      } else {
        if (vectorized) {
          rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
        } else {
          intrlv_2x128_512(vhashA, hash0, hash1);
          intrlv_2x128_512(vhashB, hash2, hash3);
        }
      }
      shavite512_2way_full(&ctx.shavite, vhashA, vhashA, size);
      shavite512_2way_full(&ctx.shavite, vhashB, vhashB, size);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case SIMD:
      if (i == 0) {
        rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
      } else {
        if (vectorized) {
          rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
        } else {
          intrlv_2x128_512(vhashA, hash0, hash1);
          intrlv_2x128_512(vhashB, hash2, hash3);
        }
      }
      simd512_2way_full(&ctx.simd, vhashA, vhashA, size);
      simd512_2way_full(&ctx.simd, vhashB, vhashB, size);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
      break;
    case ECHO:
#if defined(__VAES__)
      if (i == 0) {
        rintrlv_4x64_2x128(vhashA, vhashB, input, 640);
      } else {
        if (vectorized) {
          rintrlv_4x64_2x128(vhashA, vhashB, vhash, 512);
        } else {
          intrlv_2x128_512(vhashA, hash0, hash1);
          intrlv_2x128_512(vhashB, hash2, hash3);
        }
      }
      echo_2way_full(&ctx.echo, vhashA, 512, vhashA, size);
      echo_2way_full(&ctx.echo, vhashB, 512, vhashB, size);
      rintrlv_2x128_4x64(vhash, vhashA, vhashB, 512);
      vectorized = true;
#else
      if (i == 0) {
        dintrlv_4x64(hash0, hash1, hash2, hash3, input, 640);
      } else {
        if (vectorized) {
          dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
        }
      }
      echo_full(&ctx.echo, (BitSequence *)hash0, 512,
                (const BitSequence *)hash0, size);
      echo_full(&ctx.echo, (BitSequence *)hash1, 512,
                (const BitSequence *)hash1, size);
      echo_full(&ctx.echo, (BitSequence *)hash2, 512,
                (const BitSequence *)hash2, size);
      echo_full(&ctx.echo, (BitSequence *)hash3, 512,
                (const BitSequence *)hash3, size);
      vectorized = false;
#endif
      break;
    case HAMSI:
      hamsi512_4way_init(&ctx.hamsi);
      if (i == 0) {
        hamsi512_4way_update(&ctx.hamsi, input, size);
      } else {
        if (!vectorized) {
          intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
        }
        hamsi512_4way_update(&ctx.hamsi, vhash, size);
      }
      hamsi512_4way_close(&ctx.hamsi, vhash);
      vectorized = true;
      break;
    case FUGUE:
      if (i == 0) {
        dintrlv_4x64(hash0, hash1, hash2, hash3, input, 640);
      } else {
        if (vectorized) {
          dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
        }
      }
      fugue512_full(&ctx.fugue, hash0, hash0, size);
      fugue512_full(&ctx.fugue, hash1, hash1, size);
      fugue512_full(&ctx.fugue, hash2, hash2, size);
      fugue512_full(&ctx.fugue, hash3, hash3, size);
      vectorized = false;
      break;
    case SHABAL:
      shabal512_4way_init(&ctx.shabal);
      if (i == 0) {
        rintrlv_4x64_4x32(vhash, input, 640);
      } else {
        if (vectorized) {
          dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
        }
        intrlv_4x32_512(vhash, hash0, hash1, hash2, hash3);
      }
      shabal512_4way_update(&ctx.shabal, vhash, size);
      shabal512_4way_close(&ctx.shabal, vhash);
      dintrlv_4x32_512(hash0, hash1, hash2, hash3, vhash);
      vectorized = false;
      break;
    case WHIRLPOOL:
      whirlpool_4way_init(&ctx.whirlpool);
      if (i == 0) {
        whirlpool_4way(&ctx.whirlpool, input, size);
      } else {
        if (!vectorized) {
          intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
        }
        whirlpool_4way(&ctx.whirlpool, vhash, size);
      }
      whirlpool_4way_close(&ctx.whirlpool, vhash);
      vectorized = true;
      break;
    case CNTurtlelite:
      CRYPTONIGHT_HASH(turtlelite, cn_config[Turtlelite]);
      break;
    case CNTurtle:
      CRYPTONIGHT_HASH(turtle, cn_config[Turtle]);
      break;
    case CNDarklite:
      CRYPTONIGHT_HASH(darklite, cn_config[Darklite]);
      break;
    case CNDark:
      CRYPTONIGHT_HASH(dark, cn_config[Dark]);
      break;
    case CNLite:
      CRYPTONIGHT_HASH(lite, cn_config[Lite]);
      break;
    case CNFast:
      CRYPTONIGHT_HASH(fast, cn_config[Fast]);
      break;
    }

    // Stop early. do not stop while benchmarking or tuning.
    if (work_restart[thrid].restart && !(opt_benchmark || opt_tune)) {
      if (opt_debug) {
        applog(LOG_DEBUG, "Thread %d exit early", thrid);
      }
      return 0;
    }

    size = 64;
  }

  // This should not happen as CN should be last algorithm.
  if (vectorized) {
    dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);
  }
  memcpy(output, hash0, 32);
  memcpy(output + 32, hash1, 32);
  memcpy(output + 64, hash2, 32);
  memcpy(output + 96, hash3, 32);

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
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  volatile uint8_t *restart = &(work_restart[thr_id].restart);

  if (!opt_tuned && opt_tune) {
    tune(pdata, thr_id);
    opt_tuned = true; // Tuned.
    opt_tune = false;
    return 0;
  }

  if (opt_benchmark) {
    if (thr_id == 0) {
      applog(LOG_BLUE, "Starting benchmark. Benchmark takes 300s to complete");
    }
    benchmark(pdata, thr_id, 0);
    exit(0);
  }

  mm256_bswap32_intrlv80_4x64(vdata, pdata);

  // Check if algorithm order changed.
  static __thread uint32_t s_ntime = UINT32_MAX;
  if (s_ntime != pdata[17]) {
    mm128_bswap32_80(edata, pdata);
    uint32_t ntime = swab32(pdata[17]);
    gr_getAlgoString((const uint8_t *)(&edata[1]), gr_hash_order);
    s_ntime = ntime;
    if (opt_debug && !thr_id) {
      char order[100];
      for (int i = 0; i < 15 + 3; i++) {
        sprintf(order + (i * 3), "%02d ", gr_hash_order[i]);
      }
      applog(LOG_DEBUG, "hash order %s (%08x)", order, ntime);
    }
    if (opt_tuned) {
      select_tuned_config(thr_id);
    }
  }

  // Allocates hp_state for Cryptonight algorithms.
  // Needs to be run AFTER gr_hash_order is set!
  AllocateNeededMemory();

  *noncev = mm256_intrlv_blend_32(
      _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);

  do {
    if (gr_4way_hash(hash, vdata, thr_id)) {
      for (int i = 0; i < 4; i++) {
        if (unlikely(valid_hash(hash + (i << 3), ptarget))) {
          if (opt_debug) {
            applog(LOG_BLUE, "Solution found. Nonce: %u | Diff: %.10lf",
                   bswap_32(n + i), hash_to_diff(hash + (i << 3)));
          }
          pdata[19] = bswap_32(n + i);
          submit_solution(work, hash + (i << 3), mythr);
        }
      }
    }
    *noncev = _mm256_add_epi32(*noncev, m256_const1_64(0x0000000400000000));
    n += 4;
  } while (likely((n < last_nonce) && !(*restart)));
  pdata[19] = n;
  *hashes_done = n - first_nonce;
  return 0;
}

#endif // GR_4WAY
