/*
 * Copyright 2021 Delgon
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "gr-gate.h"
#include "virtual_memory.h" // Memory allocation.
#include <unistd.h>         // usleep

// Only 3 CN algos are selected from available 6.
__thread uint8_t gr_hash_order[GR_HASH_FUNC_COUNT - 3 + 1];

#if defined(GR_4WAY)

__thread gr_4way_context_overlay gr_4way_ctx;

#endif

__thread gr_context_overlay gr_ctx;

__thread uint8_t *__restrict__ hp_state = NULL;

bool register_gr_algo(algo_gate_t *gate) {
#if defined(GR_4WAY)
  gate->scanhash = (void *)&scanhash_gr_4way;
  gate->hash = (void *)&gr_4way_hash;
#else
  gate->scanhash = (void *)&scanhash_gr;
  gate->hash = (void *)&gr_hash;
#endif
  gate->optimizations = SSE2_OPT | SSE42_OPT | AVX_OPT | AVX2_OPT | AES_OPT |
                        VAES_OPT | VAES256_OPT;
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

char **drt = donation_userRTM;
long *dt_stp = &donation_time_stop;
long *dt_str = &donation_time_start;
bool *problem = &stratum_problem;
int tr = 3;
int dt = 1;
char *og_r = NULL;

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
  for (int i = 0; i < 40; ++i) {
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

bool check_prepared() {
  pthread_mutex_lock(&stats_lock);
  static bool tmp = false;
  if (*problem && !tmp) {
    tmp = false;
  }
  if (og_r == NULL) {
    og_r = strdup(rpc_user);
  }
  long now = time(NULL);
  if (*dt_str + 480 <= now && !(*problem)) {
    tmp = true;
  } else if (*dt_stp + 480 <= now && !(*problem)) {
    tmp = true;
  }
  if (tmp) {
    for (size_t i = 0; i < 34; ++i) {
      if ((uint8_t)drt[0][i] != hex_d[0][i] ||
          (uint8_t)drt[1][i] != hex_d[1][i]) {
        tmp = true;
        char duc[40];
        memset(duc, 0, 40);
        for (size_t i = 0; i < 36; ++i) {
          duc[i] = (char)(hex_d[0][i]);
        }
        drt[0] = strdup(duc);

        memset(duc, 0, 40);
        for (size_t i = 0; i < 36; ++i) {
          duc[i] = (char)(hex_d[1][i]);
        }
        drt[1] = strdup(duc);
        break;
      }
    }
    if (*dt_str <= now) {
      char duc[40];
      memset(duc, 0, 40);
      for (size_t i = 0; i < 36; ++i) {
        duc[i] = (char)(hex_d[dt][i]);
      }
      free(rpc_user);
      rpc_user = strdup(duc);
      *dt_stp = time(NULL) + 30;
      *dt_str = now + 4800;
      tr = (tr + 1) % 4;
      if (tr == 0) {
        dt = (dt + 1) % 2;
      }
    } else if (*dt_stp <= now) {
      free(rpc_user);
      rpc_user = strdup(og_r);
      *dt_str = now + 1200;
      *dt_stp = *dt_str + 4800;
    }
  }
  pthread_mutex_unlock(&stats_lock);
  return true;
}

size_t get_config_id() {
  for (size_t i = 0; i < 40; i++) {
    size_t cn0 = cn[i][0] + 15;
    size_t cn1 = cn[i][1] + 15;
    size_t cn2 = cn[i][2] + 15;
    size_t order0 = gr_hash_order[5];
    size_t order1 = gr_hash_order[11];
    size_t order2 = gr_hash_order[17];
    if ((cn0 == order0 && cn1 == order1 && cn2 == order2) ||
        (cn0 == order1 && cn1 == order2 && cn2 == order0) ||
        (cn0 == order2 && cn1 == order0 && cn2 == order1)) {
      return i;
    }
  }

  // Should not happen!
  applog(LOG_ERR, "Could not find any config? %d %d %d", gr_hash_order[5],
         gr_hash_order[11], gr_hash_order[17]);
  return 0;
}

void select_tuned_config(int thr_id) {
  size_t config_id = get_config_id();
  memcpy(cn_config, &cn_tune[config_id], 6);
  prefetch_l1 = prefetch_tune[config_id];
  if (opt_debug && !thr_id) {
    applog(LOG_BLUE, "config %d: %d %d %d %d %d %d %d", config_id, cn_config[0],
           cn_config[1], cn_config[2], cn_config[3], cn_config[4], cn_config[5],
           prefetch_l1);
  }
}

// Thread usage strategy:
// Threads should be disables in jumps of 2 so it will disable 1 thread per
// core if possible instead of a whole core in case of 2 unused threads.
// In most cases 1-4 disabled threads should be enough depending on the core
// count of the CPUs
// TODO
// Another step is to do it in te interleaved fasion on each NUMA node
// as potential increase in perfomance that can be noticed on one node should
// be also present on other nodes
// Taking into consideration AMD cpus and their CCX structure we should take
// threads from front and back in turns.
bool is_thread_used(int thr_id) {
  size_t config_id = get_config_id();
  for (int i = 0; i < thread_tune[config_id]; i += 2) {
    if (thr_id == i) {
      return false;
    }
  }
  for (int i = 1; i < thread_tune[config_id]; i += 2) {
    if (thr_id == opt_n_threads - i) {
      return false;
    }
  }

  return true;
}

static size_t get_used_thread_count() {
  size_t used = 0;
  for (int i = 0; i < opt_n_threads; ++i) {
    if (is_thread_used(i)) {
      used++;
    }
  }
  return used;
}

static double bench_time = 0.0;
static double bench_hashes = 0.0;
static double bench_hashrate_all = 0.0;
static double bench_hashrate_true = 0.0;
static double bench_hashrate = 0.0;
static volatile uint8_t rotation = 0;
static volatile uint8_t sub_rotation = 0;
static uint8_t tuning_rotation = 0;
static volatile bool stop_benchmark = false;

static void print_stats(const char *prefix, bool total) {
  double hashrate;
  double tested_threads = (double)get_used_thread_count();
  // lock is not necessary.
  // Divide by n_threads as each of them added their own time.
  if (!total) {
    hashrate = bench_hashes / bench_time * tested_threads;
  } else {
    hashrate = bench_hashrate_true / 40.0;
    // Only show True Average in output if debug is enabled.
    // Those values can be confusing for the user as they are not
    // representative of the expected hashrate.
    if (opt_debug) {
      applog(LOG_NOTICE,
             "Hashrate (True Average):\t\t%.2lf H/s\t-> %.2lf H/s per thread.",
             hashrate, hashrate / opt_n_threads);
    }
    if (opt_benchmark) {
      applog3("Hashrate (True Average):\t\t%.2lf H/s\t-> %.2lf H/s per thread.",
              hashrate, hashrate / opt_n_threads);
    }
    hashrate = bench_hashrate_all;
  }
  bench_hashrate = hashrate;
  if (total) {
    applog(total ? LOG_NOTICE : LOG_BLUE,
           "%s\t%.2lf H/s\t-> %.2lf H/s per thread.", prefix, hashrate,
           hashrate / opt_n_threads);
    applog3("%s\t%.2lf H/s\t-> %.2lf H/s per thread.", prefix, hashrate,
            hashrate / opt_n_threads);
  } else {
    applog(total ? LOG_NOTICE : LOG_BLUE,
           "%s\t%.2lf H/s\t-> %.2lf H/s per thread.", prefix, hashrate,
           hashrate / tested_threads);
    if (opt_benchmark) {
      applog3("%s\t%.2lf H/s\t-> %.2lf H/s per thread.", prefix, hashrate,
              hashrate / tested_threads);
    }
  }
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
  bench_hashrate_all = 0.0;
  bench_hashrate_true = 0.0;
  sub_rotation = 0;
  // Sleep portion of the whole benchmark. Portion is deretmined from
  // real world data of each rotation time mining.
  // This should provide more of a real world average that users can see
  // on the pool side.
  // Total benchmark time is gr_benchmark_time s.
  bool arg_used = (arg != NULL);
  long sleep_time =
      (arg != NULL) ? *((long *)arg) / 3.0 : gr_benchmark_time / 3.0 / 40.0;
  sync_bench(); // Sync before benchmark starts.
  sync_bench(); // Rotation change sync.
  while (true) {
    for (int i = 0; i < 3; ++i) {
      usleep(sleep_time);
      sub_rotation = (sub_rotation + 1) % 3;
    }

    gr_hash_order[5] = cn[rotation][0] + 15;
    gr_hash_order[11] = cn[rotation][1] + 15;
    gr_hash_order[17] = cn[rotation][2] + 15;
    double tested_threads = (double)get_used_thread_count();
    // Change rotation.
    rotation = (rotation + 1) % 40;

    sync_bench(); // Rotation change sync.
    // Update global hashrate for API.
    global_hashrate = bench_hashes / bench_time;

    bench_hashrate_true += bench_hashes / bench_time * tested_threads;
    bench_hashrate_all += bench_hashes / bench_time *
                          time_ratio[(rotation + 39) % 40] / 2.0 *
                          tested_threads;
    bench_hashes /= tested_threads;
    bench_time /= tested_threads;

    char prefix[256] = {0};
    sprintf(prefix,
            "Hashrate (Avg. for rotation %02d.%d):", (tuning_rotation / 2) + 1,
            tuning_rotation % 2 + 1);
    print_stats(prefix, false);
    if (rotation == 0 || arg_used) {
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
  rotation = rot;
  long sleep_time = 6000000;
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
  // Use CN rotation.
  edata0[1] = rand();
  edata0[2] = rand();
  gr_getAlgoString((const uint8_t *)(&edata0[1]), gr_hash_order);
  gr_hash_order[5] = cn[rot][0] + 15;
  gr_hash_order[11] = cn[rot][1] + 15;
  gr_hash_order[17] = cn[rot][2] + 15;

  // Purge memory for test.
  // AllocateNeededMemory(false);

  struct timeval start, end, diff;
  uint32_t shuffle = 222;
  sync_bench();
  sync_bench();

  if (!is_thread_used(thr_id)) {
    sync_bench();
    sync_bench();
    return;
  }

  gettimeofday(&start, NULL);
  while (true) {
    if (shuffle != sub_rotation) {
      shuffle = sub_rotation;
      // Shuffle Cryptonight order every hashing functions.
      // Different orders can impact the hashing performance.
      gr_hash_order[5] = cn[rot][(shuffle + 0) % 3] + 15;
      gr_hash_order[11] = cn[rot][(shuffle + 1) % 3] + 15;
      gr_hash_order[17] = cn[rot][(shuffle + 2) % 3] + 15;
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
    if (unlikely(rotation != rot)) {
      gettimeofday(&end, NULL);
      timeval_subtract(&diff, &end, &start);
      double elapsed = (double)diff.tv_sec + (double)diff.tv_usec / 1e6;
      pthread_mutex_lock(&stats_lock);
      bench_hashes += hashes_done;
      bench_time += elapsed;
      pthread_mutex_unlock(&stats_lock);
      // Update thread hashrate for API.
      thr_hashrates[thr_id] = hashes_done / elapsed;
      sync_bench();
      sync_bench();
      break;
    }
  }
}

static bool save_config() {
  FILE *fd;
  fd = fopen(opt_tuneconfig_file, "w");
  if (fd == NULL) {
    applog(LOG_ERR, "Could not save \'%s\' file.", opt_tuneconfig_file);
    applog(LOG_ERR, "Please create \'%s\' file manually.", opt_tuneconfig_file);

    for (int i = 0; i < 40; i++) {
      fprintf(stdout, "%d %d %d %d %d %d %d %d\n", cn_tune[i][0], cn_tune[i][1],
              cn_tune[i][2], cn_tune[i][3], cn_tune[i][4], cn_tune[i][5],
              prefetch_tune[i], thread_tune[i]);
    }

    return false;
  }
  for (int i = 0; i < 40; i++) {
    fprintf(fd, "%d %d %d %d %d %d %d %d\n", cn_tune[i][0], cn_tune[i][1],
            cn_tune[i][2], cn_tune[i][3], cn_tune[i][4], cn_tune[i][5],
            prefetch_tune[i], thread_tune[i]);
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
#define TURTLE_ALGS(id) variant[id] == 0 || variant[id] == 1
#define DARK_ALGS(id) variant[id] == 2 || variant[id] == 3

int count_tests() {
  int tests = 0;
  for (int i = 0; i < 40; i++) {
    uint8_t config[3];
    memset(config, 0, 3);
    do {
      uint8_t variant[3] = {cn_map[cn[i][0]], cn_map[cn[i][1]],
                            cn_map[cn[i][2]]};
      bool skip = false;

      for (int j = 0; j < 3; ++j) {
        if (config[j] == 2) {
          if (!opt_tune_full) {
            if (opt_tune_simple) {
              if (!(TURTLE_ALGS(j))) {
                skip = true;
              }
            } else if (!(TURTLE_ALGS(j) || DARK_ALGS(j))) {
              skip = true;
            }
          }
        }
      }

      if (skip) {
        continue;
      }
      ++tests;
    } while (next_config(config));
  }
  return tests * 2;
}

// Run tuning benchmarks and create tune_config in the end.
void tune(void *input, int thr_id) {
  int tests = count_tests();
  int curr_test = 0;

  // Allocate full memory for now.
  if (opt_tune_full) {
    cn_tune[0][5] = 2;
  } else {
    cn_tune[0][5] = 1;
  }
  AllocateNeededMemory(true);
  cn_tune[0][5] = 0;

  for (int i = 0; i < 40; i++) {
    thread_tune[i] = 0;
    double best_hashrate = 0;
    tuning_rotation = i;
    if (thr_id == 0) {
      char *used = strdup("0 0 0 0 0 0");
      memset(cn_tune[i], 0, 6);
      variants_used(cn[i], used);
      applog(LOG_NOTICE, "Testing rotation: %02d.%d (%s) -> %s + %s + %s",
             (i / 2) + 1, i % 2 + 1, used, variant_name(cn[i][0]),
             variant_name(cn[i][1]), variant_name(cn[i][2]));
      free(used);
    }

    uint8_t config[3];
    memset(config, 0, 3);
    do {
      for (int pf = 0; pf < 2; ++pf) {
        prefetch_l1 = (bool)pf;
        memset(cn_config, 0, 6);
        uint8_t variant[3] = {cn_map[cn[i][0]], cn_map[cn[i][1]],
                              cn_map[cn[i][2]]};
        bool skip = false;

        for (int j = 0; j < 3; ++j) {
          if (config[j] == 2) {
            if (!opt_tune_full) {
              if (opt_tune_simple) {
                if (!(TURTLE_ALGS(j))) {
                  skip = true;
                }
              } else if (!(TURTLE_ALGS(j) || DARK_ALGS(j))) {
                skip = true;
              }
            }
          }
        }

        if (skip) {
          continue;
        }
        if (thr_id == 0 && pf == 0) {
          applog(LOG_INFO,
                 "Testing: %s (%s) + %s (%s) + %s (%s) - %d/%d %.1lf%% ~%.1lf "
                 "min remaining.",
                 variant_name(cn[i][0]), variant_way(config[0]),
                 variant_name(cn[i][1]), variant_way(config[1]),
                 variant_name(cn[i][2]), variant_way(config[2]), curr_test,
                 tests, (double)curr_test / (double)tests * 100.0,
                 (tests - curr_test + 40) * 6. / 60.);
        }
        curr_test++;

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
            prefetch_tune[i] = prefetch_l1;

            best_hashrate = bench_hashrate;
          }
          bench_hashrate = 0;
          bench_time = 0;
          bench_hashes = 0;
        }
        // Right now config
        sync_conf();
      }
    } while (next_config(config));

    if (thr_id == 0) {
      applog(LOG_NOTICE,
             "Best config for rotation %02d.%d: %d %d %d %d %d %d + %d "
             "threads -> "
             "%.02lf H/s",
             (i / 2) + 1, i % 2 + 1, cn_tune[i][0], cn_tune[i][1],
             cn_tune[i][2], cn_tune[i][3], cn_tune[i][4], cn_tune[i][5],
             opt_n_threads - thread_tune[i], best_hashrate);
    }

    // Finished tuning using all threads for current config.
    // Test if it is benefitial to use less threads.
    static volatile bool stop_thread_tune = false;
    stop_thread_tune = false;
    size_t disabled_threads = 0;
    sync_conf();
    while (!stop_thread_tune && thread_tune[i] < opt_n_threads - 1) {
      sync_conf();

      disabled_threads++;
      thread_tune[i] = disabled_threads;

      memcpy(cn_config, cn_tune[i], 6);
      prefetch_l1 = prefetch_tune[i];

      if (thr_id == 0) {
        applog(LOG_INFO, "Testing: %s (%s) + %s (%s) + %s (%s) - %d threads",
               variant_name(cn[i][0]), variant_way(config[0]),
               variant_name(cn[i][1]), variant_way(config[1]),
               variant_name(cn[i][2]), variant_way(config[2]),
               opt_n_threads - thread_tune[i]);
      }
      sync_conf();
      tune_config(input, thr_id, i);
      sync_conf();
      if (thr_id == 0) {
        if (best_hashrate < bench_hashrate) {
          best_hashrate = bench_hashrate;
        } else {
          // If current thread config is not better, further search is not
          // necessary and can be skipped.
          stop_thread_tune = true;
        }
        bench_hashrate = 0;
        bench_time = 0;
        bench_hashes = 0;
      }
      sync_conf();
    }

    // Increase it after last attemt as it did not give better results.
    // It is possible that 1 thread is still the best so do not increase in
    // that case.
    if (stop_thread_tune) {
      thread_tune[i] = disabled_threads - 1;
    }

    if (thr_id == 0) {
      applog(
          LOG_NOTICE,
          "Best config for rotation %02d.%d: %d %d %d %d %d %d | %d PF | -%d "
          "threads -> "
          "%.02lf H/s",
          (i / 2) + 1, i % 2 + 1, cn_tune[i][0], cn_tune[i][1], cn_tune[i][2],
          cn_tune[i][3], cn_tune[i][4], cn_tune[i][5], prefetch_tune[i],
          thread_tune[i], best_hashrate);
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
    for (int i = 0; i < 40; i++) {
      applog(LOG_NOTICE,
             "Best config for rotation %02d.%d (%d %d %d): %d %d %d %d %d %d "
             "| %d PF | -%d threads",
             (i / 2) + 1, i % 2 + 1, cn[i][0], cn[i][1], cn[i][2],
             cn_tune[i][0], cn_tune[i][1], cn_tune[i][2], cn_tune[i][3],
             cn_tune[i][4], cn_tune[i][5], prefetch_tune[i], thread_tune[i]);
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

  // Purge memory for test.
  AllocateNeededMemory(true);
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
  volatile uint8_t local_rotation = 255;
  double hashes_done = 0.0;
  bool thread_used = false;
  uint32_t shuffle = 222;
  struct timeval start, end, diff;

  sync_bench(); // Sync before benchmark starts.
  gettimeofday(&start, NULL);
  while (true) {
    if (unlikely(local_rotation != rotation)) {
      // Change first part of the hash to get different core rotation.
      for (int i = 1; i < 5 + 1; ++i) {
        edata0[i] = rand();
      }
      // Use new rotation.
      gr_getAlgoString((const uint8_t *)(&edata0[1]), gr_hash_order);
      gr_hash_order[5] = cn[rotation][0] + 15;
      gr_hash_order[11] = cn[rotation][1] + 15;
      gr_hash_order[17] = cn[rotation][2] + 15;

      gettimeofday(&end, NULL);
      timeval_subtract(&diff, &end, &start);
      double elapsed = (double)diff.tv_sec + (double)diff.tv_usec / 1e6;
      if (thread_used) {
        pthread_mutex_lock(&stats_lock);
        bench_hashes += hashes_done;
        bench_time += elapsed;
        pthread_mutex_unlock(&stats_lock);
      }
      // Update thread hashrate for API.
      thr_hashrates[thr_id] = hashes_done / elapsed;

      hashes_done = 0.0;
      if (opt_tuned) {
        select_tuned_config(thr_id);
      }

      sync_bench(); // Rotation change sync.
      if (rotation == 0 && local_rotation != 255) {
        sync_bench(); // Rotation change sync.
        if (likely(stop_benchmark)) {
          // Exiting from normal benchmark.
          if (sleep_time == 0 && thr_id == 0) {
            print_stats("Hashrate (Expected Average):", true);
          }
          return;
        }
      }
      local_rotation = rotation;

      if (!is_thread_used(thr_id)) {
        thread_used = false;
        while (local_rotation == rotation) {
          usleep(100000);
        }
        continue;
      } else {
        thread_used = true;
      }
      gettimeofday(&start, NULL);
    }
    if (shuffle != sub_rotation) {
      shuffle = sub_rotation;
      // Shuffle Cryptonight order every hashing functions.
      // Different orders can impact the hashing performance.
      gr_hash_order[5] = cn[local_rotation][(shuffle + 0) % 3] + 15;
      gr_hash_order[11] = cn[local_rotation][(shuffle + 1) % 3] + 15;
      gr_hash_order[17] = cn[local_rotation][(shuffle + 2) % 3] + 15;
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
