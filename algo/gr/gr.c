#include "gr-gate.h"
#include "virtual_memory.h"

int gr_hash(void *output, const void *input, int thrid) {
  uint64_t hash[8] __attribute__((aligned(64)));
  gr_context_overlay ctx;
  memcpy(&ctx, &gr_ctx, sizeof(ctx));
  void *in = (void *)input;
  int size = 80;

  for (int i = 0; i < 15 + 3; i++) {
    const uint8_t algo = gr_hash_order[i];
    switch (algo) {
    case BLAKE:
      sph_blake512_init(&ctx.blake);
      sph_blake512(&ctx.blake, in, size);
      sph_blake512_close(&ctx.blake, hash);
      break;
    case BMW:
      sph_bmw512_init(&ctx.bmw);
      sph_bmw512(&ctx.bmw, in, size);
      sph_bmw512_close(&ctx.bmw, hash);
      break;
    case GROESTL:
#if defined(__AES__)
      groestl512_full(&ctx.groestl, (char *)hash, (char *)in, size << 3);
#else
      sph_groestl512_init(&ctx.groestl);
      sph_groestl512(&ctx.groestl, in, size);
      sph_groestl512_close(&ctx.groestl, hash);
#endif
      break;
    case SKEIN:
      sph_skein512_init(&ctx.skein);
      sph_skein512(&ctx.skein, in, size);
      sph_skein512_close(&ctx.skein, hash);
      break;
    case JH:
      sph_jh512_init(&ctx.jh);
      sph_jh512(&ctx.jh, in, size);
      sph_jh512_close(&ctx.jh, hash);
      break;
    case KECCAK:
      sph_keccak512_init(&ctx.keccak);
      sph_keccak512(&ctx.keccak, in, size);
      sph_keccak512_close(&ctx.keccak, hash);
      break;
    case LUFFA:
      luffa_full(&ctx.luffa, (BitSequence *)hash, 512, (const BitSequence *)in,
                 size);
      break;
    case CUBEHASH:
      cubehash_full(&ctx.cube, (byte *)hash, 512, (byte *)in, size);
      break;
    case SHAVITE:
      shavite512_full(&ctx.shavite, hash, in, size);
      break;
    case SIMD:
      simd_full(&ctx.simd, (BitSequence *)hash, (const BitSequence *)in,
                size << 3);
      break;
    case ECHO:
#if defined(__AES__)
      echo_full(&ctx.echo, (BitSequence *)hash, 512, (const BitSequence *)in,
                size);
#else
      sph_echo512_init(&ctx.echo);
      sph_echo512(&ctx.echo, in, size);
      sph_echo512_close(&ctx.echo, hash);
#endif
      break;
    case HAMSI:
      sph_hamsi512_init(&ctx.hamsi);
      sph_hamsi512(&ctx.hamsi, in, size);
      sph_hamsi512_close(&ctx.hamsi, hash);
      break;
    case FUGUE:
#if defined(__AES__)
      fugue512_full(&ctx.fugue, hash, in, size);
#else
      sph_fugue512_full(&ctx.fugue, hash, in, size);
#endif
      break;
    case SHABAL:
      sph_shabal512_init(&ctx.shabal);
      sph_shabal512(&ctx.shabal, in, size);
      sph_shabal512_close(&ctx.shabal, hash);
      break;
    case WHIRLPOOL:
      sph_whirlpool512_full(&ctx.whirlpool, hash, in, size);
      break;
    case CNTurtlelite:
      cryptonight_turtlelite_hash(in, hash);
      break;
    case CNTurtle:
      cryptonight_turtle_hash(in, hash);
      break;
    case CNDarklite:
      cryptonight_darklite_hash(in, hash);
      break;
    case CNDark:
      cryptonight_dark_hash(in, hash);
      break;
    case CNLite:
      cryptonight_lite_hash(in, hash);
      break;
    case CNFast:
      cryptonight_fast_hash(in, hash);
      break;
    }

    // Stop early.
    if (work_restart[thrid].restart && !opt_benchmark) {
      if (opt_debug) {
        applog(LOG_DEBUG, "Thread %d exit early", thrid);
      }
      return 0;
    }
    in = (void *)hash;
    size = 64;
  }
  memcpy(output, hash, 32);
  return 1;
}

int scanhash_gr(struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                struct thr_info *mythr) {

  uint32_t _ALIGN(128) hash32[8];
  uint32_t _ALIGN(128) edata[20];
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  const uint32_t first_nonce = pdata[19];
  const int thr_id = mythr->id;
  uint32_t nonce = first_nonce;
  volatile uint8_t *restart = &(work_restart[thr_id].restart);

  if (hp_state == NULL) {
    hp_state = (uint8_t *)AllocateMemory(1 << 21);
  }

  if (opt_benchmark) {
    benchmark(pdata, thr_id);
    diff_to_hash(ptarget, 0.05 / 65536.0);
  }

  mm128_bswap32_80(edata, pdata);

  // Check if algorithm order changed.
  static __thread uint32_t s_ntime = UINT32_MAX;
  if (s_ntime != pdata[17]) {
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
  }

  do {
    edata[19] = nonce;
    if (gr_hash(hash32, edata, thr_id)) {
      if (unlikely(valid_hash(hash32, ptarget))) {
        pdata[19] = bswap_32(nonce);
        submit_solution(work, hash32, mythr);
      }
    }
    nonce++;
  } while (likely(nonce < max_nonce && !(*restart)));
  pdata[19] = nonce;
  *hashes_done = pdata[19] - first_nonce;
  return 0;
}
