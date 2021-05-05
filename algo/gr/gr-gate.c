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

static double bench_time = 0.0;
static double bench_hashes = 0.0;
static uint8_t rotation = 0;

static void print_stats(const char *prefix, bool same_line) {
  double hashrate;
  char hr_units[4] = {0};

  // lock is not necessary.
  hashrate = bench_hashes / bench_time;
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

// Detached thread for changing rotation every 1.5s.
// Prints data every rotation.
void *statistic_thread() {
  struct timeval start, end, diff;
  double elapsed;
  gettimeofday(&start, NULL);
  while (true) {
    usleep(3000000);
    // Change rotation.
    rotation = (rotation + 1) % 20;
    gettimeofday(&end, NULL);
    timeval_subtract(&diff, &end, &start);
    elapsed = (double)diff.tv_sec + (double)diff.tv_usec / 1e6;
    bench_time = elapsed;
    if (rotation == 0) {
      // Print permanently after full 20 rotations.
      print_stats("Hashrate (Avg): ", false);
    } else {
      print_stats("Hashrate (Avg): ", true);
    }
  }
}

// Values for 20 CN rotations.
static const uint8_t cn[20][3] = {
    {0, 1, 2}, {0, 1, 3}, {0, 1, 4}, {0, 1, 5}, {0, 2, 3}, {0, 2, 4}, {0, 2, 5},
    {0, 3, 4}, {0, 3, 5}, {0, 4, 5}, {1, 2, 3}, {1, 2, 4}, {1, 2, 5}, {1, 3, 4},
    {1, 3, 5}, {1, 4, 5}, {2, 3, 4}, {2, 3, 5}, {2, 4, 5}, {3, 4, 5}};

void benchmark(void *input, int thr_id) {
  pthread_t pthr;
  if (thr_id == 0) {
    pthread_create(&pthr, NULL, &statistic_thread, NULL);
  }

  uint32_t edata[20] __attribute__((aligned(64)));
#if defined(GR_4WAY)
  uint32_t hash[8 * 4] __attribute__((aligned(64)));
  uint32_t vdata[20 * 4] __attribute__((aligned(64)));
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  mm256_bswap32_intrlv80_4x64(vdata, input);
  uint32_t n = 0;
#else
  uint32_t hash[8] __attribute__((aligned(64)));
  mm128_bswap32_80(edata, input);
#endif
  uint8_t local_rotation = 255;
#if defined(GR_4WAY)
  const int iters = 1;
#else
  const int iters = 2;
#endif
  while (true) {
    for (int i = 0; i < iters; i++) {
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
      }
#if defined(GR_4WAY)
      // Make sure nonces are increased for each hash. Same hashes will result
      // in better data locality on CN algos leading to better/innaccurate
      // results.
      *noncev = mm256_intrlv_blend_32(
          _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);
      gr_4way_hash(hash, vdata, thr_id);
#else
      // Increase nonce.
      edata[19]++;
      gr_hash(hash, edata, thr_id);
#endif
    }
    pthread_mutex_lock(&stats_lock);
#if defined(GR_4WAY)
    bench_hashes += iters * 4;
#else
    bench_hashes += iters;
#endif
    pthread_mutex_unlock(&stats_lock);
  }
}
