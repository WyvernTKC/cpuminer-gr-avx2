#include "gr-gate.h"
#include <unistd.h> // usleep

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
  gate->optimizations = SSE2_OPT | AES_OPT | VAES_OPT | AVX_OPT | AVX2_OPT;
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

void select_tuned_config() {
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
          if (opt_debug) {
            applog(LOG_BLUE, "config %d: %d %d %d %d %d %d", i, cn_config[0],
                   cn_config[1], cn_config[2], cn_config[3], cn_config[4],
                   cn_config[5]);
          }
          return;
        }
      }
    }
  }
  // Should not get to this point.
  applog(LOG_ERR, "Could not find any config? %d %d %d", gr_hash_order[5],
         gr_hash_order[11], gr_hash_order[17]);
  return;
}

static double bench_time = 0.0;
static double bench_hashes = 0.0;
static double bench_hashrate = 0.0;
static uint8_t rotation = 0;
static volatile bool stop_benchmark = false;

static void print_stats(const char *prefix, bool same_line) {
  double hashrate;
  char hr_units[4] = {0};

  // lock is not necessary.
  hashrate = bench_hashes / bench_time;
  bench_hashrate = hashrate;
  scale_hash_for_display(&hashrate, hr_units);
  if (same_line) {
    pthread_mutex_unlock(&applog_lock);
    printf("                      %s\t%.2lf %sH/s (%.2lfs)\t-> %.3lf %sH/s per "
           "thread.\r",
           prefix, hashrate, hr_units, bench_time, hashrate / opt_n_threads,
           hr_units);
    fflush(stdout);
    pthread_mutex_unlock(&applog_lock);

  } else {
    applog(LOG_BLUE, "%s\t%.2lf %sH/s (%.2lfs)\t-> %.3lf %sH/s per thread.",
           prefix, hashrate, hr_units, bench_time, hashrate / opt_n_threads,
           hr_units);
  }
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
  bool infinite = true;
  long sleep_time = 6000000;
  if (arg != NULL) {
    infinite = false;
    sleep_time = *((long *)arg);
  }
  struct timeval start, end, diff;
  double elapsed;
  sync_bench(); // Sync before benchmark starts.
  sync_bench(); // Rotation change. Threads start with new rotation.
  while (true) {
    gettimeofday(&start, NULL);
    usleep(sleep_time);
    // Change rotation.
    rotation = (rotation + 1) % 20;
    gettimeofday(&end, NULL);
    timeval_subtract(&diff, &end, &start);
    elapsed = (double)diff.tv_sec + (double)diff.tv_usec / 1e6;
    bench_time += elapsed;
    if (rotation == 0) {
      // Print permanently after full 20 rotations.
      print_stats("Hashrate (Avg): ", false);
      if (!infinite) {
        stop_benchmark =
            true;     // Make sure it is true before other threads sync.
        sync_bench(); // Config change sync.
        return NULL;
      }
    } else {
      print_stats("Hashrate (Avg): ", true);
    }
    sync_bench();
  }
}

#ifdef __AVX2__

static uint8_t cn_map[6] = {3, 2, 5, 4, 1, 0};

static void tune_config(void *input, int thr_id, int rot) {
  srand(time(NULL) + thr_id);
  rotation = 19;
  long sleep_time = 12500000;
  pthread_t pthr;
  if (thr_id == 0) {
    pthread_create(&pthr, NULL, &statistic_thread, &sleep_time);
  }
  uint32_t edata[4] __attribute__((aligned(64)));
  uint32_t hash[8 * 4] __attribute__((aligned(64)));
  uint32_t vdata[20 * 4] __attribute__((aligned(64)));
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  mm256_bswap32_intrlv80_4x64(vdata, input);
  uint32_t n = 10000 * thr_id;
  *noncev = mm256_intrlv_blend_32(
      _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);

  // Use CN rotation.
  edata[1] = rand();
  edata[2] = rand();
  gr_getAlgoString((const uint8_t *)(&edata[1]), gr_hash_order);
  gr_hash_order[5] = cn[rot][0] + 15;
  gr_hash_order[11] = cn[rot][1] + 15;
  gr_hash_order[17] = cn[rot][2] + 15;
  // Set desired CN config.
  sync_bench();
  sync_bench();
  while (true) {
    gr_4way_hash(hash, vdata, thr_id);
    *noncev = _mm256_add_epi32(*noncev, m256_const1_64(0x0000000400000000));
    n += 4;
    pthread_mutex_lock(&stats_lock);
    bench_hashes += 4;
    pthread_mutex_unlock(&stats_lock);
    if (rotation == 0) {
      sync_bench();
      break;
    }
  }
}

static bool save_config() {
  char *filename = "tune_config";
  FILE *fd;
  fd = fopen(filename, "w+");
  if (fd == NULL) {
    applog(LOG_ERR, "Could not save tune_config file");
    return false;
  }
  for (int i = 0; i < 20; i++) {
    fprintf(fd, "%d %d %d %d %d %d\n", cn_tune[i][0], cn_tune[i][1],
            cn_tune[i][2], cn_tune[i][3], cn_tune[i][4], cn_tune[i][5]);
  }
  fclose(fd);
  return true;
}

// Run tuning benchmarks and create tune_config in the end.
void tune(void *input, int thr_id) {
  if (thr_id == 0) {
    // Test save empty config to see if we have permissions.
    if (!save_config()) {
      applog(LOG_ERR, "Check if you have permission to file 'tune_config'");
      exit(0);
    }
  }

  for (int i = 0; i < 20; i++) {
    int best_hashrate = 0;
    if (thr_id == 0) {
      memset(cn_tune[i], 0, 6);
      applog(LOG_NOTICE, "Testing rotation: %d", i);
    }
    for (int config = 0; config < 8; config++) {
      memset(cn_config, 0, 6);
      cn_config[cn_map[cn[i][0]]] = (config & 1) >> 0;
      cn_config[cn_map[cn[i][1]]] = (config & 2) >> 1;
      cn_config[cn_map[cn[i][2]]] = (config & 4) >> 2;
      sync_conf();
      tune_config(input, thr_id, i);
      sync_conf();
      if (thr_id == 0) {
        // TODO
        // Do not set the improvement if Fast variant is included.
        // Possible bug/inaccuracy in benchmarking with it set as 1.
        // Can be reproduced with 5000 series Ryzens.
        if (cn_map[cn[i][0]] != 5 && cn_map[cn[i][1]] != 5 &&
            cn_map[cn[i][2]] != 5) {
          if (best_hashrate < bench_hashrate) {
            if (opt_debug) {
              applog(LOG_DEBUG, "%d -> %d | %d -> %d | %d -> %d", cn[i][0],
                     (config & 1) >> 0, cn[i][1], (config & 2) >> 1, cn[i][2],
                     (config & 4) >> 2);
            }
            cn_tune[i][cn_map[cn[i][0]]] = (config & 1) >> 0;
            cn_tune[i][cn_map[cn[i][1]]] = (config & 2) >> 1;
            cn_tune[i][cn_map[cn[i][2]]] = (config & 4) >> 2;
            if (opt_debug) {
              applog(LOG_DEBUG, "Config for rotation %d: %d %d %d %d %d %d", i,
                     cn_tune[i][0], cn_tune[i][1], cn_tune[i][2], cn_tune[i][3],
                     cn_tune[i][4], cn_tune[i][5]);
            }
            best_hashrate = bench_hashrate;
          }
        }
        bench_hashrate = 0;
        bench_time = 0;
        bench_hashes = 0;
      }
      // Right now config
      sync_conf();
    }
    if (thr_id == 0) {
      applog(LOG_NOTICE, "Best config for rotation %d: %d %d %d %d %d %d", i,
             cn_tune[i][0], cn_tune[i][1], cn_tune[i][2], cn_tune[i][3],
             cn_tune[i][4], cn_tune[i][5]);
    }
  }
  if (thr_id == 0) {
    for (int i = 0; i < 20; i++) {
      applog(LOG_NOTICE,
             "Best config for rotation %d (%d %d %d): %d %d %d %d %d %d", i,
             cn[i][0], cn[i][1], cn[i][2], cn_tune[i][0], cn_tune[i][1],
             cn_tune[i][2], cn_tune[i][3], cn_tune[i][4], cn_tune[i][5]);
    }
    opt_tune = false;
    opt_tuned = true;
    save_config();
  }
  sync_conf();
}

#endif // __AVX2__ // GR_4WAY

void benchmark(void *input, int thr_id, long sleep_time) {
  srand(time(NULL) + thr_id);
  pthread_t pthr;
  if (thr_id == 0) {
    pthread_create(&pthr, NULL, &statistic_thread,
                   sleep_time ? &sleep_time : NULL);
  }

  uint32_t edata[20] __attribute__((aligned(64)));
#if defined(GR_4WAY)
  uint32_t hash[8 * 4] __attribute__((aligned(64)));
  uint32_t vdata[20 * 4] __attribute__((aligned(64)));
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  mm256_bswap32_intrlv80_4x64(vdata, input);
  uint32_t n = 10000 * thr_id;
  *noncev = mm256_intrlv_blend_32(
      _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);
#else
  uint32_t hash[8] __attribute__((aligned(64)));
  mm128_bswap32_80(edata, input);
#endif
  uint8_t local_rotation = 255;

  sync_bench(); // Sync before benchmark starts.
  while (true) {
    // gr_hash_order is calculated once per rotation as that is how it is done
    // in scanhash_gr.
    if (likely(local_rotation != rotation)) {
      local_rotation = rotation;
      // Change first part of the hash to get different core rotation.
      edata[1] = rand();
      edata[2] = rand();

      // Use new rotation.
      gr_getAlgoString((const uint8_t *)(&edata[1]), gr_hash_order);
      gr_hash_order[5] = cn[rotation][0] + 15;
      gr_hash_order[11] = cn[rotation][1] + 15;
      gr_hash_order[17] = cn[rotation][2] + 15;
      if (opt_tuned) {
        select_tuned_config();
      }

      sync_bench(); // Rotation change sync.
      if (rotation == 0) {
        if (likely(stop_benchmark)) {
          return;
        }
      }
    }
#if defined(GR_4WAY)
    // Make sure nonces are increased for each hash. Same hashes will result
    // in better data locality on CN algos leading to better/innaccurate
    // results.
    gr_4way_hash(hash, vdata, thr_id);
    *noncev = _mm256_add_epi32(*noncev, m256_const1_64(0x0000000400000000));
    n += 4;
#else
    // Increase nonce.
    edata[19]++;
    gr_hash(hash, edata, thr_id);
#endif
    // Calculated hash. Do not count half finished hahshes.
    pthread_mutex_lock(&stats_lock);
#if defined(GR_4WAY)
    bench_hashes += 4;
#else
    bench_hashes += 1;
#endif
    pthread_mutex_unlock(&stats_lock);
  }
}

void benchmark_configs(void *input, int thr_id) {
  int best_config = 0;
  int best_hashrate = 0;

  for (int i = 0; i < (1 << 6); i++) {
    // Set new cn_config to test.
    cn_config[0] = (i & 1) >> 0;
    cn_config[1] = (i & 2) >> 1;
    cn_config[2] = (i & 4) >> 2;
    cn_config[3] = (i & 8) >> 3;
    cn_config[4] = (i & 16) >> 4;
    cn_config[5] = (i & 32) >> 5;
    if (thr_id == 0) {
      applog(LOG_NOTICE, "Testing Cryptonigh --cn-config %d,%d,%d,%d,%d,%d",
             cn_config[0], cn_config[1], cn_config[2], cn_config[3],
             cn_config[4], cn_config[5]);

      // Reset benchamrk variables to default.
      bench_time = 0.0;
      bench_hashes = 0.0;
      bench_hashrate = 0.0;
      rotation = 0;
    }
    sync_conf();
    stop_benchmark = false;
    sync_conf();
    benchmark(input, thr_id, 1000000);

    // Check if this config is better.
    if (thr_id == 0) {
      if (bench_hashrate > best_hashrate) {
        best_hashrate = bench_hashrate;
        best_config = i;
      }
    }
  }
  // Show best config.
  if (thr_id == 0) {
    applog(LOG_NOTICE, "Best --cn-config %d,%d,%d,%d,%d,%d",
           (best_config & 1) >> 0, (best_config & 2) >> 1,
           (best_config & 4) >> 2, (best_config & 8) >> 3,
           (best_config & 16) >> 4, (best_config & 32) >> 5);
  }
}
