#include "gr-gate.h"
#include "virtual_memory.h" // Memory allocation.
#include <unistd.h>         // usleep

// Only 3 CN algos are selected from available 6.
__thread uint8_t gr_hash_order[GR_HASH_FUNC_COUNT - 3 + 1];

#if defined(GR_4WAY)

__thread gr_4way_context_overlay gr_4way_ctx;

#endif

__thread gr_context_overlay gr_ctx;

__thread uint8_t *hp_state = NULL;

bool register_gr_algo(algo_gate_t *gate) {
#if defined(GR_4WAY)
  gate->scanhash = (void *)&scanhash_gr_4way;
  gate->hash = (void *)&gr_4way_hash;
#else
  gate->scanhash = (void *)&scanhash_gr;
  gate->hash = (void *)&gr_hash;
#endif
  gate->optimizations = SSE2_OPT | SSE42_OPT | AVX_OPT | AVX2_OPT | VAES_OPT | VAES256_OPT | AES_OPT;
  opt_target_factor = 65536.0;
  return true;
}

static void selectAlgo(const uint8_t nibble, bool *selectedAlgos,
                       uint8_t *selectedIndex, int algoCount,
                       int *currentCount) {
  uint8_t algoDigit = (nibble & 0x0F) % algoCount;
  if (!selectedAlgos[algoDigit]) {
    selectedAlgos[algoDigit] = true;
    selectedIndex[currentCount[0]] = algoDigit;
    currentCount[0] = currentCount[0] + 1;
  }
  algoDigit = (nibble >> 4) % algoCount;
  if (!selectedAlgos[algoDigit]) {
    selectedAlgos[algoDigit] = true;
    selectedIndex[currentCount[0]] = algoDigit;
    currentCount[0] = currentCount[0] + 1;
  }
}

void gr_getAlgoString(const uint8_t *block, uint8_t *selectedAlgoOutput) {
  // Select Core algos.
  bool selectedCoreAlgo[15];

  for (int i = 0; i < 15; i++) {
    selectedCoreAlgo[i] = false;
  }

  uint8_t core_algos[15];
  int selectedCoreCount = 0;
  for (int i = 0; i < 32; i++) {
    selectAlgo(block[i], selectedCoreAlgo, core_algos, 15, &selectedCoreCount);
    if (selectedCoreCount == 15) {
      break;
    }
  }
  if (selectedCoreCount < 15) {
    for (int i = 0; i < 15; i++) {
      if (!selectedCoreAlgo[i]) {
        core_algos[selectedCoreCount] = i;
        selectedCoreCount++;
      }
    }
  }

  // Select Core algos.
  bool selectedCNAlgo[6];

  for (int i = 0; i < 6; i++) {
    selectedCNAlgo[i] = false;
  }

  uint8_t cn_algos[6];
  int selectedCNCount = 0;
  for (int i = 0; i < 32; i++) {
    selectAlgo(block[i], selectedCNAlgo, cn_algos, 6, &selectedCNCount);
    if (selectedCNCount == 6) {
      break;
    }
  }
  if (selectedCNCount < 6) {
    for (int i = 0; i < 6; i++) {
      if (!selectedCNAlgo[i]) {
        cn_algos[selectedCNCount] = i;
        selectedCNCount++;
      }
    }
  }

  selectedCNCount = 0;
  selectedCoreCount = 0;
  // Create proper algo order.
  for (int i = 0; i < 15 + 3; i++) {
    if (i % 6 == 5) {
      // Add CN algo.
      selectedAlgoOutput[i] = cn_algos[selectedCNCount++] + 15;
      i++;
      if (i == 18) {
        break;
      }
    }
    selectedAlgoOutput[i] = core_algos[selectedCoreCount++];
  }
}

// Mapping of gr_harh_order CN to cn-config - lightest to heaviest order.
// Config:  Turtlelite, Turtle, Darklite, Dark, Lite, Fast.
// Gr_Hash: Dark, Darklite, Fast, Lite, Turtle, Turtlelite
static uint8_t cn_map[6] = {3, 2, 5, 4, 1, 0};

static size_t GetMaxConfigSize(uint8_t *config, uint8_t *used) {
  // Memory requirements for each CN variant
  size_t cn_req[6] = {262144, 262144, 524288, 524288, 1048576, 2097152};
  // Check tune/config if given variant uses 2way that requires 2x memory.
  // cn_config should contain only 0 values in non GR_4WAY.
  for (int i = 0; i < 6; i++) {
    if (config[i] == CN_4WAY) {
      cn_req[i] *= 4;
    } else if (config[i] == CN_2WAY) {
      cn_req[i] *= 2;
    } else {
      cn_req[i] *= 1;
    }
  }

  size_t order[3] = {cn_map[used[0]], cn_map[used[1]], cn_map[used[2]]};

  size_t max =
      cn_req[order[0]] > cn_req[order[1]] ? cn_req[order[0]] : cn_req[order[1]];
  max = max > cn_req[order[2]] ? max : cn_req[order[2]];

  return max;
}

static size_t GetMaxTuneSize() {
  size_t max = 2097152;
  const size_t max_2pages = max * 2;
  const size_t max_4pages = max * 4;
  for (int i = 0; i < 20; ++i) {
    if (cn_tune[i][4] == 2 || cn_tune[i][5] == 1) {
      max = max < max_2pages ? max_2pages : max;
    }
    if (cn_tune[i][5] == 2) {
      max = max < max_4pages ? max_4pages : max;
    }
  }

  return max;
}

void AllocateNeededMemory(bool max) {
  uint8_t used[3] = {gr_hash_order[5] - 15, gr_hash_order[11] - 15,
                     gr_hash_order[17] - 15};
  size_t size = max ? GetMaxTuneSize() : GetMaxConfigSize(cn_config, used);

  // Purges previous memory allocation and creates new one.
  PrepareMemory((void **)&hp_state, size);
}

void select_tuned_config(int thr_id) {
  for (size_t i = 0; i < 20; i++) {
    if (cn[i][0] + 15 == gr_hash_order[5] ||
        cn[i][0] + 15 == gr_hash_order[11] ||
        cn[i][0] + 15 == gr_hash_order[17]) {
      if (cn[i][1] + 15 == gr_hash_order[5] ||
          cn[i][1] + 15 == gr_hash_order[11] ||
          cn[i][1] + 15 == gr_hash_order[17]) {
        if (cn[i][2] + 15 == gr_hash_order[5] ||
            cn[i][2] + 15 == gr_hash_order[11] ||
            cn[i][2] + 15 == gr_hash_order[17]) {
          memcpy(cn_config, &cn_tune[i], 6);
          if (opt_debug && !thr_id) {
            applog(LOG_BLUE, "config %d: %d %d %d %d %d %d", i, cn_config[0],
                   cn_config[1], cn_config[2], cn_config[3], cn_config[4],
                   cn_config[5]);
          }
          return;
        }
      }
    }
  }
  if (!thr_id) {
    // Should not get to this point.
    applog(LOG_ERR, "Could not find any config? %d %d %d", gr_hash_order[5],
           gr_hash_order[11], gr_hash_order[17]);
  }
  return;
}

static double bench_time = 0.0;
static double bench_hashes = 0.0;
static double bench_time_all = 0.0;
static double bench_hashes_all = 0.0;
static double bench_time_true = 0.0;
static double bench_hashes_true = 0.0;
static double bench_hashrate = 0.0;
static uint8_t rotation = 0;
static uint8_t tuning_rotation = 0;
static volatile bool stop_benchmark = false;

static void print_stats(const char *prefix, bool total) {
  double hashrate;

  // lock is not necessary.
  // Divide by n_threads as each of them added their own time.
  if (!total) {
    hashrate = bench_hashes / bench_time * opt_n_threads;
  } else {
    hashrate = bench_hashes_true / bench_time_true * opt_n_threads;
    bench_time = bench_time_true;
    applog(LOG_NOTICE,
           "Hashrate (True Average):\t\t%.2lf H/s\t-> %.2lf H/s per thread.",
           hashrate, hashrate / opt_n_threads);
    hashrate = bench_hashes_all / bench_time_all * opt_n_threads;
    bench_time = bench_time_all;
  }
  bench_hashrate = hashrate;
  applog(total ? LOG_NOTICE : LOG_BLUE,
         "%s\t%.2lf H/s\t-> %.2lf H/s per thread.", prefix, hashrate,
         hashrate / opt_n_threads);
  bench_time = 0;
  bench_hashes = 0;
}

static void sync_lock(const int locks) {
  static volatile int done = 0;

  pthread_mutex_lock(&stats_lock);
  done++;
  if (done != locks) {
    pthread_cond_wait(&sync_cond, &stats_lock);
  } else {
    done = 0;
    pthread_cond_broadcast(&sync_cond);
  }
  pthread_mutex_unlock(&stats_lock);
}

static void sync_conf() { sync_lock(opt_n_threads); }

static void sync_bench() { sync_lock(opt_n_threads + 1); }

// Detached thread for changing rotation every 1.5s.
// Prints data every rotation.
void *statistic_thread(void *arg) {
  bench_time_all = 0.0;
  bench_hashes_all = 0.0;
  bench_time_true = 0.0;
  bench_hashes_true = 0.0;
  sync_bench(); // Sync before benchmark starts.
  sync_bench(); // Rotation change sync.
  while (true) {
    if (arg != NULL) {
      // Sleep for predefined time period.
      usleep(*((long *)arg));
    } else {
      // Sleep portion of the whole benchmark. Portion is deretmined from
      // real world data of each rotation time mining.
      // This should provide more of a real world average that users can see
      // on the pool side.
      // Total benchmark time is gr_benchmark_time s.
      usleep(gr_benchmark_time / 20.);
    }
    // Change rotation.
    rotation = (rotation + 1) % 20;
    sync_bench(); // Rotation change sync.
    if (arg != NULL) {
      bench_time_all += bench_time;
      bench_hashes_all += bench_hashes;
    } else {
      bench_time_true += bench_time;
      bench_hashes_true += bench_hashes;
      if (opt_benchmark_old) {
        bench_time *= time_ratio_old[(rotation + 19) % 20];
        bench_hashes *= time_ratio_old[(rotation + 19) % 20];
      } else {
        bench_time *= time_ratio[(rotation + 19) % 20];
        bench_hashes *= time_ratio[(rotation + 19) % 20];
      }
      bench_time_all += bench_time;
      bench_hashes_all += bench_hashes;
    }

    char prefix[256] = {0};
    sprintf(prefix, "Hashrate (Avg. for rotation %02d):", tuning_rotation + 1);
    print_stats(prefix, false);
    if (rotation == 0) {
      // Print permanently after full 20 rotations.
      // Make sure it is true before other threads sync.
      stop_benchmark = true;
      sync_bench(); // Config change sync.
      return NULL;
    } else {
      tuning_rotation++;
    }
  }
}

static void tune_config(void *input, int thr_id, int rot) {
  srand(thr_id);
  rotation = 19;
  long sleep_time = 12500000;
  pthread_t pthr;
  if (thr_id == 0) {
    pthread_create(&pthr, NULL, &statistic_thread, &sleep_time);
  }

  uint32_t n = 10000 * thr_id;
  uint32_t edata0[20] __attribute__((aligned(64)));
  mm128_bswap32_80(edata0, input);
  edata0[19] = n;
#if defined(GR_4WAY)
  uint32_t hash[8 * 4] __attribute__((aligned(64)));
  uint32_t vdata[20 * 4] __attribute__((aligned(64)));
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  mm256_bswap32_intrlv80_4x64(vdata, input);
  *noncev = mm256_intrlv_blend_32(
      _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);
#else
  uint32_t hash[8 * 2] __attribute__((aligned(64)));
  uint32_t edata1[20] __attribute__((aligned(64)));
  mm128_bswap32_80(edata1, input);
  edata1[19] = n + 1;
#endif
  double hashes_done = 0.0;
  uint32_t shuffle = 0;
  // Use CN rotation.
  edata0[1] = rand();
  edata0[2] = rand();
  gr_getAlgoString((const uint8_t *)(&edata0[1]), gr_hash_order);
  gr_hash_order[5] = cn[rot][0] + 15;
  gr_hash_order[11] = cn[rot][1] + 15;
  gr_hash_order[17] = cn[rot][2] + 15;

  // Purge memory for test.
  AllocateNeededMemory(false);

  struct timeval start, end, diff;

  sync_bench();
  sync_bench();
  gettimeofday(&start, NULL);
  while (true) {
#if defined(GR_4WAY)
    // Make sure nonces are increased for each hash. Same hashes will result
    // in better data locality on CN algos leading to better/innaccurate
    // results.
    gr_4way_hash(hash, vdata, thr_id);
    *noncev = _mm256_add_epi32(*noncev, m256_const1_64(0x0000000400000000));
    hashes_done += 4.0;
#else
    // Increase nonce.
    edata0[19] += 2;
    edata1[19] += 2;
    gr_hash(hash, edata0, edata1, thr_id);
    hashes_done += 2.0;
#endif
    if (unlikely(rotation == 0)) {
      gettimeofday(&end, NULL);
      timeval_subtract(&diff, &end, &start);
      double elapsed = (double)diff.tv_sec + (double)diff.tv_usec / 1e6;
      pthread_mutex_lock(&stats_lock);
      bench_hashes += hashes_done;
      bench_time += elapsed;
      pthread_mutex_unlock(&stats_lock);
      sync_bench();
      sync_bench();
      break;
    } else {
      // Shuffle Cryptonight order every hashing functions.
      // Different orders can impact the hashing performance.
      ++shuffle;
      if (shuffle < 3) {
        gr_hash_order[5] = cn[rot][(shuffle + 0) % 3] + 15;
        gr_hash_order[11] = cn[rot][(shuffle + 1) % 3] + 15;
        gr_hash_order[17] = cn[rot][(shuffle + 2) % 3] + 15;
      } else {
        gr_hash_order[5] = cn[rot][(shuffle + 0) % 3] + 15;
        gr_hash_order[11] = cn[rot][(shuffle + 2) % 3] + 15;
        gr_hash_order[17] = cn[rot][(shuffle + 1) % 3] + 15;
        if (shuffle == 6) {
          shuffle = 0;
        }
      }
    }
  }
}

static bool save_config() {
  FILE *fd;
  fd = fopen(opt_tuneconfig_file, "w");
  if (fd == NULL) {
    applog(LOG_ERR, "Could not save \'%s\' file.", opt_tuneconfig_file);
    return false;
  }
  for (int i = 0; i < 20; i++) {
    fprintf(fd, "%d %d %d %d %d %d\n", cn_tune[i][0], cn_tune[i][1],
            cn_tune[i][2], cn_tune[i][3], cn_tune[i][4], cn_tune[i][5]);
  }
  fclose(fd);
  return true;
}

// Config is a table of 3 values from 0-2.
static bool next_config(uint8_t *config) {
#ifdef __AVX2__
  static const int max_val = 2;
#else
  static const int max_val = 1;
#endif

  bool increment = true;
  for (size_t i = 0; i < 3; ++i) {
    if (increment) {
      if (config[i] == max_val) {
        config[i] = 0;
        if (i == 2) {
          return false;
        }
      } else {
        config[i]++;
        increment = false;
      }
    } else {
      break;
    }
  }
  return true;
}

static char *variant_name(const uint8_t variant) {
  switch (variant) {
  case 0:
    return "Dark";
  case 1:
    return "Darklite";
  case 2:
    return "Fast";
  case 3:
    return "Lite";
  case 4:
    return "Turtle";
  case 5:
    return "Turtlelite";
  }
  return "Unknown";
}

static char *variant_way(const uint8_t way) {
  switch (way) {
  case CN_4WAY:
    return "4way";
  case CN_2WAY:
    return "2way";
  default:
    return "1way";
  }
}

static void variants_used(const uint8_t *ids, char *used) {
  for (int i = 0; i < 3; ++i) {
    used[cn_map[ids[i]] * 2] = 'X';
  }
}

// Used in tune to detect if the
#define TURTLE(id) variant[id] == 0 || variant[id] == 1
#define DARK(id) variant[id] == 2 || variant[id] == 3

// Run tuning benchmarks and create tune_config in the end.
void tune(void *input, int thr_id) {
  for (int i = 0; i < 20; i++) {
    double best_hashrate = 0;
    tuning_rotation = i;
    if (thr_id == 0) {
      char *used = strdup("0 0 0 0 0 0");
      memset(cn_tune[i], 0, 6);
      variants_used(cn[i], used);
      applog(LOG_NOTICE, "Testing rotation: %02d (%s) -> %s + %s + %s", i + 1,
             used, variant_name(cn[i][0]), variant_name(cn[i][1]),
             variant_name(cn[i][2]));
      free(used);
    }

    uint8_t config[3];
    memset(config, 0, 3);
    do {
      memset(cn_config, 0, 6);
      uint8_t variant[3] = {cn_map[cn[i][0]], cn_map[cn[i][1]],
                            cn_map[cn[i][2]]};
      bool skip = false;

      for (int j = 0; j < 3; ++j) {
        if (config[j] == 2) {
          if (!opt_tune_full) {
            if (opt_tune_simple) {
              if (!(TURTLE(j))) {
                skip = true;
              }
            } else if (!(TURTLE(j) || DARK(j))) {
              skip = true;
            }
          }
        }
      }

      if (skip) {
        continue;
      }

      if (thr_id == 0) {
        applog(LOG_INFO, "Testing: %s (%s) + %s (%s) + %s (%s)",
               variant_name(cn[i][0]), variant_way(config[0]),
               variant_name(cn[i][1]), variant_way(config[1]),
               variant_name(cn[i][2]), variant_way(config[2]));
      }

      cn_config[variant[0]] = config[0];
      cn_config[variant[1]] = config[1];
      cn_config[variant[2]] = config[2];
      sync_conf();
      tune_config(input, thr_id, i);
      sync_conf();
      if (thr_id == 0) {
        if (best_hashrate < bench_hashrate) {
          cn_tune[i][variant[0]] = config[0];
          cn_tune[i][variant[1]] = config[1];
          cn_tune[i][variant[2]] = config[2];

          best_hashrate = bench_hashrate;
        }
        bench_hashrate = 0;
        bench_time = 0;
        bench_hashes = 0;
      }
      // Right now config
      sync_conf();
    } while (next_config(config));

    if (thr_id == 0) {
      applog(LOG_NOTICE,
             "Best config for rotation %02d: %d %d %d %d %d %d -> %.02lf H/s",
             i + 1, cn_tune[i][0], cn_tune[i][1], cn_tune[i][2], cn_tune[i][3],
             cn_tune[i][4], cn_tune[i][5], best_hashrate);
      char *used = strdup("0 0 0 0 0 0");
      variants_used(cn[i], used);
      applog(LOG_NOTICE, "%s -> %s (%s) + %s (%s) + %s (%s)", used,
             variant_name(cn[i][0]), variant_way(cn_tune[i][cn_map[cn[i][0]]]),
             variant_name(cn[i][1]), variant_way(cn_tune[i][cn_map[cn[i][1]]]),
             variant_name(cn[i][2]), variant_way(cn_tune[i][cn_map[cn[i][2]]]));
      free(used);
    }
  }
  if (thr_id == 0) {
    for (int i = 0; i < 20; i++) {
      applog(LOG_NOTICE,
             "Best config for rotation %02d (%d %d %d): %d %d %d %d %d %d",
             i + 1, cn[i][0], cn[i][1], cn[i][2], cn_tune[i][0], cn_tune[i][1],
             cn_tune[i][2], cn_tune[i][3], cn_tune[i][4], cn_tune[i][5]);
    }
    opt_tune = false;
    opt_tuned = true;
    rotation = 0;
    tuning_rotation = 0;
    save_config();
  }
  sync_conf();
}

void benchmark(void *input, int thr_id, long sleep_time) {
  for (int i = 0; i < 160; i++) {
    ((uint8_t *)input)[i] = i;
  }

  srand(thr_id);
  pthread_t pthr;
  if (thr_id == 0) {
    pthread_create(&pthr, NULL, &statistic_thread,
                   sleep_time ? &sleep_time : NULL);
  }

  uint32_t n = 10000 * thr_id;
  uint32_t edata0[20] __attribute__((aligned(64)));
  mm128_bswap32_80(edata0, input);
  edata0[19] = n;
#if defined(GR_4WAY)
  uint32_t hash[8 * 4] __attribute__((aligned(64)));
  uint32_t vdata[20 * 4] __attribute__((aligned(64)));
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  mm256_bswap32_intrlv80_4x64(vdata, input);
  *noncev = mm256_intrlv_blend_32(
      _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);
#else
  uint32_t hash[8 * 2] __attribute__((aligned(64)));
  uint32_t edata1[20] __attribute__((aligned(64)));
  mm128_bswap32_80(edata1, input);
  edata1[19] = n + 1;
#endif
  uint8_t local_rotation = 255;
  double hashes_done = 0.0;
  uint32_t shuffle = 0;

  struct timeval start, end, diff;

  sync_bench(); // Sync before benchmark starts.
  gettimeofday(&start, NULL);
  while (true) {
    if (unlikely(local_rotation != rotation)) {
      gettimeofday(&end, NULL);
      timeval_subtract(&diff, &end, &start);
      double elapsed = (double)diff.tv_sec + (double)diff.tv_usec / 1e6;
      pthread_mutex_lock(&stats_lock);
      bench_hashes += hashes_done;
      bench_time += elapsed;
      pthread_mutex_unlock(&stats_lock);

      hashes_done = 0.0;
      shuffle = 1;
      // Change first part of the hash to get different core rotation.
      for (int i = 1; i < 5 + 1; ++i) {
        edata0[i] = rand();
      }
      // Use new rotation.
      gr_getAlgoString((const uint8_t *)(&edata0[1]), gr_hash_order);
      gr_hash_order[5] = cn[rotation][0] + 15;
      gr_hash_order[11] = cn[rotation][1] + 15;
      gr_hash_order[17] = cn[rotation][2] + 15;

      if (opt_tuned) {
        select_tuned_config(thr_id);
      }

      // Purge memory for test.
      AllocateNeededMemory(false);

      sync_bench(); // Rotation change sync.
      if (rotation == 0 && local_rotation != 255) {
        sync_bench(); // Rotation change sync.
        if (likely(stop_benchmark)) {
          // Exiting from normal benchmark.
          if (sleep_time == 0 && thr_id == 0) {
            print_stats("Hashrate (Est. Pool Average):", true);
          }
          return;
        }
      }
      local_rotation = rotation;
      gettimeofday(&start, NULL);
    } else if (!opt_benchmark_old) {
      // Shuffle Cryptonight order every hashing functions.
      // Different orders can impact the hashing performance.
      if (shuffle < 3) {
        gr_hash_order[5] = cn[local_rotation][(shuffle + 0) % 3] + 15;
        gr_hash_order[11] = cn[local_rotation][(shuffle + 1) % 3] + 15;
        gr_hash_order[17] = cn[local_rotation][(shuffle + 2) % 3] + 15;
        ++shuffle;
      } else {
        gr_hash_order[5] = cn[local_rotation][(shuffle + 0) % 3] + 15;
        gr_hash_order[11] = cn[local_rotation][(shuffle + 2) % 3] + 15;
        gr_hash_order[17] = cn[local_rotation][(shuffle + 1) % 3] + 15;
        ++shuffle;
        if (shuffle == 6) {
          shuffle = 0;
        }
      }
    }
#if defined(GR_4WAY)
    // Make sure nonces are increased for each hash. Same hashes will result
    // in better data locality on CN algos leading to better/innaccurate
    // results.
    gr_4way_hash(hash, vdata, thr_id);
    *noncev = _mm256_add_epi32(*noncev, m256_const1_64(0x0000000400000000));
    hashes_done += 4.0;
#else
    // Increase nonce.
    edata0[19] += 2;
    edata1[19] += 2;
    gr_hash(hash, edata0, edata1, thr_id);
    hashes_done += 2.0;
#endif
  }
}
