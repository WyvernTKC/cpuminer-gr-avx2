#include "gr-gate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../blake/sph_blake.h"
#include "../blake/blake-hash-4way.h"
#include "../bmw/sph_bmw.h"
#include "../bmw/bmw-hash-4way.h"
#include "../groestl/sph_groestl.h"
#include "../groestl/aes_ni/hash-groestl.h"
#include "../jh/sph_jh.h"
#include "../jh/jh-hash-4way.h"
#include "../keccak/sph_keccak.h"
#include "../keccak/keccak-hash-4way.h"
#include "../skein/sph_skein.h"
#include "../skein/skein-hash-4way.h"
#include "../luffa/sph_luffa.h"
#include "../luffa/luffa-hash-2way.h"
#include "../cubehash/sph_cubehash.h"
#include "../cubehash/cube-hash-2way.h"
#include "../shavite/sph_shavite.h"
#include "../shavite/shavite-hash-2way.h"
#include "../simd/sph_simd.h"
#include "../simd/simd-hash-2way.h"
#include "../echo/sph_echo.h"
#include "../echo/aes_ni/hash_api.h"
#include "../hamsi/sph_hamsi.h"
#include "../hamsi/hamsi-hash-4way.h"
#include "../fugue/sph_fugue.h"
#include "../shabal/sph_shabal.h"
#include "../shabal/shabal-hash-4way.h"
#include "../whirlpool/sph_whirlpool.h"
#include "../whirlpool/whirlpool-hash-4way.h"
#include "../sha/sph_sha2.h"
#include "../tiger/sph_tiger.h"
#include "../lyra2/lyra2.h"
#include "../haval/sph-haval.h"
#include "../gost/sph_gost.h"
#include "cryptonote/cryptonight_dark.h"
#include "cryptonote/cryptonight_dark_lite.h"
#include "cryptonote/cryptonight_fast.h"
#include "cryptonote/cryptonight.h"
#include "cryptonote/cryptonight_lite.h"
#include "cryptonote/cryptonight_soft_shell.h"
#include "cryptonote/cryptonight_turtle.h"
#include "cryptonote/cryptonight_turtle_lite.h"
#include <sys/mman.h>
//#define MEMORY          2097152
#define MEMORY          4194304

#if defined(_MSC_VER)
#define THREADV __declspec(thread)
#else
#define THREADV __thread
#endif
THREADV uint8_t *hp_state = NULL;
THREADV int hp_allocated = 0;
void slow_hash_allocate_state(void)
{
    if(hp_state != NULL)
        return;

#if defined(_MSC_VER) || defined(__MINGW32__)
    SetLockPagesPrivilege(GetCurrentProcess(), TRUE);
    hp_state = (uint8_t *) VirtualAlloc(hp_state, MEMORY, MEM_LARGE_PAGES |
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
  defined(__DragonFly__)
    hp_state = mmap(0, MEMORY, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
#else
    hp_state = mmap(0, MEMORY, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
#endif
    if(hp_state == MAP_FAILED)
        hp_state = NULL;
#endif
    hp_allocated = 1;
    if(hp_state == NULL)
    {
        hp_allocated = 0;
        hp_state = (uint8_t *) malloc(MEMORY);
    }
}
void slow_hash_free_state(void)
{
    if(hp_state == NULL)
        return;

    if(!hp_allocated)
        free(hp_state);
    else
    {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(hp_state, MEMORY, MEM_RELEASE);
#else
        munmap(hp_state, MEMORY);
#endif
    }

    hp_state = NULL;
    hp_allocated = 0;
}

int64_t gr_get_max64() {
   return 0x7ffLL;
}
#ifdef __AVX2__
bool register_gr_algo( algo_gate_t* gate ) {
  gate->scanhash = (void*)&scanhash_gr_4way;
  gate->hash = (void*)&gr_hash_4way;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT;
  gate->get_max64 = (void*)&gr_get_max64;
  gate->set_target = (void*)&scrypt_set_target;
  return true;
};
#else
bool register_gr_algo( algo_gate_t* gate ) {
  gate->scanhash = (void*)&scanhash_gr;
  gate->hash = (void*)&gr_hash;
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->get_max64 = (void*)&gr_get_max64;
  gate->set_target = (void*)&scrypt_set_target;
  return true;
};
#endif

enum Algo {
        BLAKE = 0,
        BMW,
        GROESTL,
        JH,
        KECCAK,
        SKEIN,
        LUFFA,
        CUBEHASH,
        SHAVITE,
        SIMD,
        ECHO,
        HAMSI,
        FUGUE,
        SHABAL,
        WHIRLPOOL,
        HASH_FUNC_COUNT
};
enum CNAlgo {
	CNDark = 0,
	CNDarklite,
	CNFast,
	CNLite,
	CNTurtle,
	CNTurtlelite,
	CN_HASH_FUNC_COUNT
};
static void selectAlgo(unsigned char nibble, bool* selectedAlgos, uint8_t* selectedIndex, int algoCount, int* currentCount) {
	uint8_t algoDigit = (nibble & 0x0F) % algoCount;
	if(!selectedAlgos[algoDigit]) {
		selectedAlgos[algoDigit] = true;
		selectedIndex[currentCount[0]] = algoDigit;
		currentCount[0] = currentCount[0] + 1;
	}
	algoDigit = (nibble >> 4) % algoCount;
	if(!selectedAlgos[algoDigit]) {
		selectedAlgos[algoDigit] = true;
		selectedIndex[currentCount[0]] = algoDigit;
		currentCount[0] = currentCount[0] + 1;
	}
}
static void getAlgoString(void *mem, unsigned int size, uint8_t* selectedAlgoOutput, int algoCount) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  unsigned int len = size/2;
  unsigned char j = 0;
  bool selectedAlgo[algoCount];
  for(int z=0; z < algoCount; z++) {
	  selectedAlgo[z] = false;
  }
  int selectedCount = 0;
  for (i=0;i<len; i++) {
	  selectAlgo(p[i], selectedAlgo, selectedAlgoOutput, algoCount, &selectedCount);
	  if(selectedCount == algoCount) {
		  break;
	  }
  }
  if(selectedCount < algoCount) {
	for(uint8_t i = 0; i < algoCount; i++) {
		if(!selectedAlgo[i]) {
			selectedAlgoOutput[selectedCount] = i;
			selectedCount++;
		}
	}
  }
}
void gr_hash(void* output, const void* input) {

	uint32_t hash[64/4];
	sph_blake512_context ctx_blake;
	sph_bmw512_context ctx_bmw;
	sph_groestl512_context ctx_groestl;
	sph_jh512_context ctx_jh;
	sph_keccak512_context ctx_keccak;
	sph_skein512_context ctx_skein;
	sph_luffa512_context ctx_luffa;
	sph_cubehash512_context ctx_cubehash;
	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
	sph_echo512_context ctx_echo;
	sph_hamsi512_context ctx_hamsi;
	sph_fugue512_context ctx_fugue;
	sph_shabal512_context ctx_shabal;
	sph_whirlpool_context ctx_whirlpool;
	sph_haval256_5_context ctx_haval;
	sph_tiger_context ctx_tiger;
	sph_gost512_context ctx_gost;
	sph_sha256_context ctx_sha;

	void *in = (void*) input;
	int size = 80;
	uint8_t selectedAlgoOutput[15] = {0};
	uint8_t selectedCNAlgoOutput[6] = {0};
	getAlgoString(&input[4], 64, selectedAlgoOutput, 15);
	getAlgoString(&input[4], 64, selectedCNAlgoOutput, 6);
	int i;
	for (i = 0; i < 18; i++)
	{
		uint8_t algo;
		uint8_t cnAlgo;
		int coreSelection;
		int cnSelection = -1;
		if(i < 5) {
			coreSelection = i;
		} else if(i < 11) {
			coreSelection = i-1;
		} else {
			coreSelection = i-2;
		}
		if(i==5) {
			coreSelection = -1;
			cnSelection = 0;
		}
		if(i==11) {
			coreSelection = -1;
			cnSelection = 1;
		}
		if(i==17) {
			coreSelection = -1;
			cnSelection = 2;
		}
		if(coreSelection >= 0) {
			algo = selectedAlgoOutput[(uint8_t)coreSelection];
		} else {
			algo = 16; // skip core hashing for this loop iteration
		}
		if(cnSelection >=0) {
			cnAlgo = selectedCNAlgoOutput[(uint8_t)cnSelection];
		} else {
			cnAlgo = 14; // skip cn hashing for this loop iteration
		}
		//selection cnAlgo. if a CN algo is selected then core algo will not be selected
		switch(cnAlgo)
		{
		 case CNDark:
			cryptonightdark_hash(in, hash, size, 1);
			break;
		 case CNDarklite:
			cryptonightdarklite_hash(in, hash, size, 1);
			break;
		 case CNFast:
			cryptonightfast_hash(in, hash, size, 1);
			break;
		 case CNLite:
			cryptonightlite_hash(in, hash, size, 1);
			break;
		 case CNTurtle:
			cryptonightturtle_hash(in, hash, size, 1);
			break;
		 case CNTurtlelite:
			cryptonightturtlelite_hash(in, hash, size, 1);
			break;
		}
		//selection core algo
		switch (algo) {
		case BLAKE:
				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, in, size);
				sph_blake512_close(&ctx_blake, hash);
				break;
		case BMW:
				sph_bmw512_init(&ctx_bmw);
				sph_bmw512(&ctx_bmw, in, size);
				sph_bmw512_close(&ctx_bmw, hash);
				break;
		case GROESTL:
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, in, size);
				sph_groestl512_close(&ctx_groestl, hash);
				break;
		case SKEIN:
				sph_skein512_init(&ctx_skein);
				sph_skein512(&ctx_skein, in, size);
				sph_skein512_close(&ctx_skein, hash);
				break;
		case JH:
				sph_jh512_init(&ctx_jh);
				sph_jh512(&ctx_jh, in, size);
				sph_jh512_close(&ctx_jh, hash);
				break;
		case KECCAK:
				sph_keccak512_init(&ctx_keccak);
				sph_keccak512(&ctx_keccak, in, size);
				sph_keccak512_close(&ctx_keccak, hash);
				break;
		case LUFFA:
				sph_luffa512_init(&ctx_luffa);
				sph_luffa512(&ctx_luffa, in, size);
				sph_luffa512_close(&ctx_luffa, hash);
				break;
		case CUBEHASH:
				sph_cubehash512_init(&ctx_cubehash);
				sph_cubehash512(&ctx_cubehash, in, size);
				sph_cubehash512_close(&ctx_cubehash, hash);
				break;
		case SHAVITE:
				sph_shavite512_init(&ctx_shavite);
				sph_shavite512(&ctx_shavite, in, size);
				sph_shavite512_close(&ctx_shavite, hash);
				break;
		case SIMD:
				sph_simd512_init(&ctx_simd);
				sph_simd512(&ctx_simd, in, size);
				sph_simd512_close(&ctx_simd, hash);
				break;
		case ECHO:
				sph_echo512_init(&ctx_echo);
				sph_echo512(&ctx_echo, in, size);
				sph_echo512_close(&ctx_echo, hash);
				break;
		case HAMSI:
				sph_hamsi512_init(&ctx_hamsi);
				sph_hamsi512(&ctx_hamsi, in, size);
				sph_hamsi512_close(&ctx_hamsi, hash);
				break;
		case FUGUE:
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, in, size);
				sph_fugue512_close(&ctx_fugue, hash);
				break;
		case SHABAL:
				sph_shabal512_init(&ctx_shabal);
				sph_shabal512(&ctx_shabal, in, size);
				sph_shabal512_close(&ctx_shabal, hash);
				break;
		case WHIRLPOOL:
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, in, size);
				sph_whirlpool_close(&ctx_whirlpool, hash);
				break;
		}
		if(cnSelection >= 0) {
			memset(&hash[8], 0, 32);
		}
		in = (void*) hash;
		size = 64;
	}
	memcpy(output, hash, 32);
}

int scanhash_gr( struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr) {
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        uint32_t _ALIGN(64) endiandata[20];
        const uint32_t first_nonce = pdata[19];
        uint32_t nonce = first_nonce;
        int thr_id = mythr->id;
		if(hp_state == NULL)
			slow_hash_allocate_state();
        if (opt_benchmark)
			((uint32_t*)ptarget)[7] = 0x00ff;
        swab32_array( endiandata, pdata, 20 );
        do {
			const uint32_t Htarg = ptarget[7];
			uint32_t hash[8];
			be32enc(&endiandata[19], nonce);
			gr_hash(hash, endiandata);
				if (hash[7] <= Htarg) {
						pdata[19] = nonce;
						*hashes_done = pdata[19] - first_nonce;
						slow_hash_free_state();
						return 1;
				}
				nonce++;
			} while (nonce < max_nonce && !work_restart[thr_id].restart);
        pdata[19] = nonce;
        *hashes_done = pdata[19] - first_nonce + 1;
		slow_hash_free_state();
        return 0;
}

#ifdef __AVX2__
void gr_hash_4way(void* output, void* output1, void* output2, void* output3, const void* input, const void* input1, const void* input2, const void* input3) {
	uint64_t hash[8] __attribute__ ((aligned (64)));
    uint64_t hash1[8] __attribute__ ((aligned (64)));
    uint64_t hash2[8] __attribute__ ((aligned (64)));
    uint64_t hash3[8] __attribute__ ((aligned (64)));
    uint64_t vhash[8*4] __attribute__ ((aligned (64)));
	uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
	uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
	blake512_4way_context ctx_blake4;
	//sph_blake512_context ctx_blake;
	bmw512_4way_context ctx_bmw;
	//sph_groestl512_context ctx_groestl;
	hashState_groestl ctx_groestl;
	//sph_jh512_context ctx_jh;
	//sph_keccak512_context ctx_keccak;
	//sph_skein512_context ctx_skein;
	skein512_4way_context ctx_skein;
	jh512_4way_context ctx_jh;
	keccak512_4way_context ctx_keccak;
	//sph_luffa512_context ctx_luffa;
	luffa_2way_context ctx_luffa;
	//sph_cubehash512_context ctx_cubehash;
	cube_2way_context ctx_cubehash;
	//sph_shavite512_context ctx_shavite;
	shavite512_2way_context ctx_shavite;
	//sph_simd512_context ctx_simd;
	simd_2way_context ctx_simd;
	//sph_echo512_context ctx_echo;
	hashState_echo ctx_echo;
	//sph_hamsi512_context ctx_hamsi;
	sph_fugue512_context ctx_fugue;
	sph_shabal512_context ctx_shabal;
	//shabal512_4way_context ctx_shabal;
	hamsi512_4way_context ctx_hamsi;
	//sph_whirlpool_context ctx_whirlpool;
	whirlpool_4way_context ctx_whirlpool;
	sph_haval256_5_context ctx_haval;
	sph_tiger_context ctx_tiger;
	sph_gost512_context ctx_gost;
	sph_sha256_context ctx_sha;
	
	void *in = (void*) input;
	void *in1 = (void*) input1;
	void *in2 = (void*) input2;
	void *in3 = (void*) input3;
	
	int size = 80;
	uint8_t selectedAlgoOutput[15] = {0};
	uint8_t selectedCNAlgoOutput[6] = {0};
	
	getAlgoString(&input[4], 64, selectedAlgoOutput, 15);
	getAlgoString(&input[4], 64, selectedCNAlgoOutput, 6);
	int i;
	for (i = 0; i < 18; i++)
	{
		uint8_t algo;
		uint8_t cnAlgo;
		int coreSelection;
		int cnSelection = -1;
		if(i < 5) {
			coreSelection = i;
		} else if(i < 11) {
			coreSelection = i-1;
		} else {
			coreSelection = i-2;
		}
		if(i==5) {
			coreSelection = -1;
			cnSelection = 0;
		}
		if(i==11) {
			coreSelection = -1;
			cnSelection = 1;
		}
		if(i==17) {
			coreSelection = -1;
			cnSelection = 2;
		}
		if(coreSelection >= 0) {
			algo = selectedAlgoOutput[(uint8_t)coreSelection];
		} else {
			algo = 16; // skip core hashing for this loop iteration
		}
		if(cnSelection >=0) {
			cnAlgo = selectedCNAlgoOutput[(uint8_t)cnSelection];
		} else {
			cnAlgo = 14; // skip cn hashing for this loop iteration
		}
		//selection cnAlgo. if a CN algo is selected then core algo will not be selected
		switch(cnAlgo)
		{
		 case CNDark:
			////printf("DARK,",i);
			cryptonightdark_hash(in, hash, size, 1);
			cryptonightdark_hash(in1, hash1, size, 1);
			cryptonightdark_hash(in2, hash2, size, 1);
			cryptonightdark_hash(in3, hash3, size, 1);
			break;
		 case CNDarklite:
			////printf("Dlite,",i);
			cryptonightdarklite_hash(in, hash, size, 1);
			cryptonightdarklite_hash(in1, hash1, size, 1);
			cryptonightdarklite_hash(in2, hash2, size, 1);
			cryptonightdarklite_hash(in3, hash3, size, 1);
			break;
		 case CNFast:
			////printf("Fast,",i);
			cryptonightfast_hash(in, hash, size, 1);
			cryptonightfast_hash(in1, hash1, size, 1);
			cryptonightfast_hash(in2, hash2, size, 1);
			cryptonightfast_hash(in3, hash3, size, 1);
			break;
		 case CNLite:
			////printf("Lite,",i);
			cryptonightlite_hash(in, hash, size, 1);
			cryptonightlite_hash(in1, hash1, size, 1);
			cryptonightlite_hash(in2, hash2, size, 1);
			cryptonightlite_hash(in3, hash3, size, 1);
			break;
		 case CNTurtle:
			////printf("Turt,",i);
			cryptonightturtle_hash(in, hash, size, 1);
			cryptonightturtle_hash(in1, hash1, size, 1);
			cryptonightturtle_hash(in2, hash2, size, 1);
			cryptonightturtle_hash(in3, hash3, size, 1);
			break;
		 case CNTurtlelite:
			////printf("TLite,",i);
			cryptonightturtlelite_hash(in, hash, size, 1);
			cryptonightturtlelite_hash(in1, hash1, size, 1);
			cryptonightturtlelite_hash(in2, hash2, size, 1);
			cryptonightturtlelite_hash(in3, hash3, size, 1);
			break;
		}
		//selection core algo
		switch (algo) {
		case BLAKE:
				//printf("Blake,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
				}
     			blake512_4way_init(&ctx_blake4);
				blake512_4way(&ctx_blake4, vhash, size);
				blake512_4way_close(&ctx_blake4, vhash);
				dintrlv_4x64_512( hash, hash1, hash2, hash3, vhash);
				//sph_blake512_init(&ctx_blake);
				//sph_blake512(&ctx_blake, in, size);
				//sph_blake512_close(&ctx_blake, hash);
				break;
		case BMW:
				//printf("BMW,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
				}
				bmw512_4way_init(&ctx_bmw);
				bmw512_4way(&ctx_bmw, vhash, size);
				bmw512_4way_close(&ctx_bmw, vhash);
				dintrlv_4x64_512( hash, hash1, hash2, hash3, vhash);
				break;
		case GROESTL:
				//printf("GRO,",i);
				init_groestl(&ctx_groestl, 64);
				update_and_final_groestl(&ctx_groestl, (char*)hash, (char*)in, size<<3 );
				init_groestl(&ctx_groestl, 64);
				update_and_final_groestl(&ctx_groestl, (char*)hash1, (char*)in1, size<<3 );
				init_groestl(&ctx_groestl, 64);
				update_and_final_groestl(&ctx_groestl, (char*)hash2, (char*)in2, size<<3 );
				init_groestl(&ctx_groestl, 64);
				update_and_final_groestl(&ctx_groestl, (char*)hash3, (char*)in3, size<<3 );
				/*sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, in, size);
				sph_groestl512_close(&ctx_groestl, hash);
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, in1, size);
				sph_groestl512_close(&ctx_groestl, hash1);
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, in2, size);
				sph_groestl512_close(&ctx_groestl, hash2);
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, in3, size);
				sph_groestl512_close(&ctx_groestl, hash3);*/
				break;
		case SKEIN:
				//printf("SKE,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
				}
				skein512_4way_init(&ctx_skein);
				skein512_4way(&ctx_skein, vhash, size);
				skein512_4way_close(&ctx_skein, vhash);
				dintrlv_4x64_512( hash, hash1, hash2, hash3, vhash);
				break;
		case JH:
				//printf("JH,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
				}
				jh512_4way_init(&ctx_jh);
				jh512_4way(&ctx_jh, vhash, size);
				jh512_4way_close(&ctx_jh, vhash);
				dintrlv_4x64_512( hash, hash1, hash2, hash3, vhash);
				break;
		case KECCAK:
				//printf("KEC,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
				}
				keccak512_4way_init(&ctx_keccak);
				keccak512_4way(&ctx_keccak, vhash, size);
				keccak512_4way_close(&ctx_keccak, vhash);
				dintrlv_4x64_512( hash, hash1, hash2, hash3, vhash);
				break;
		case LUFFA:
				//printf("LUFFA,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
				}
				luffa_2way_init( &ctx_luffa, 512 );
				luffa_2way_update_close( &ctx_luffa, vhashA, vhashA, size );
     			luffa_2way_init( &ctx_luffa, 512 );
     			luffa_2way_update_close( &ctx_luffa, vhashB, vhashB, size );
				dintrlv_2x128_512( hash, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );
				//sph_luffa512_init(&ctx_luffa);
				//sph_luffa512(&ctx_luffa, in, size);
				//sph_luffa512_close(&ctx_luffa, hash);
				break;
		case CUBEHASH:
				//printf("CUBE,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
				}
				cube_2way_init( &ctx_cubehash, 512, 16, 32 );
				cube_2way_update_close( &ctx_cubehash, vhashA, vhashA, size );
				cube_2way_init( &ctx_cubehash, 512, 16, 32 );
				cube_2way_update_close( &ctx_cubehash, vhashB, vhashB, size );
				dintrlv_2x128_512( hash, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );
				//sph_cubehash512_init(&ctx_cubehash);
				//sph_cubehash512(&ctx_cubehash, in, size);
				//sph_cubehash512_close(&ctx_cubehash, hash);
				break;
		case SHAVITE:
				//printf("SHAV,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
				}
				shavite512_2way_init(&ctx_shavite);
				shavite512_2way_update_close(&ctx_shavite, vhashA, vhashA, size );
				shavite512_2way_init(&ctx_shavite);
				shavite512_2way_update_close(&ctx_shavite, vhashB, vhashB, size );
				dintrlv_2x128_512( hash, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );
				//sph_shavite512_init(&ctx_shavite);
				//sph_shavite512(&ctx_shavite, in, size);
				//sph_shavite512_close(&ctx_shavite, hash);
				break;
		case SIMD:
				//printf("SIMD,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
					rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
				}
				simd_2way_init( &ctx_simd, 512 );
				simd_2way_update_close( &ctx_simd, vhashA, vhashA, size<<3 );
				simd_2way_init( &ctx_simd, 512 );
				simd_2way_update_close( &ctx_simd, vhashB, vhashB, size<<3 );
				dintrlv_2x128_512( hash, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );
				//sph_simd512_init(&ctx_simd);
				//sph_simd512(&ctx_simd, in, size);
				//sph_simd512_close(&ctx_simd, hash);
				break;
		case ECHO:
				//printf("ECHO,",i);
				init_echo(&ctx_echo, 512);
				update_final_echo( &ctx_echo, (BitSequence *)hash,(const BitSequence *) in, size<<3 );
				init_echo(&ctx_echo, 512);
				update_final_echo( &ctx_echo, (BitSequence *)hash1,(const BitSequence *) in1, size<<3 );
				init_echo(&ctx_echo, 512);
				update_final_echo( &ctx_echo, (BitSequence *)hash2,(const BitSequence *) in2, size<<3 );
				init_echo(&ctx_echo, 512);
				update_final_echo( &ctx_echo, (BitSequence *)hash3,(const BitSequence *) in3, size<<3 );
				//sph_echo512_init(&ctx_echo);
				//sph_echo512(&ctx_echo, in, size);
				//sph_echo512_close(&ctx_echo, hash);
				break;
		case HAMSI:
				//printf("HAMSI,",i);
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
				}
				hamsi512_4way_init(&ctx_hamsi);
				hamsi512_4way(&ctx_hamsi, vhash, size);
				hamsi512_4way_close(&ctx_hamsi, vhash);
				dintrlv_4x64_512( hash, hash1, hash2, hash3, vhash);
				break;
		case FUGUE:
				//printf("FUG,",i);
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, in, size);
				sph_fugue512_close(&ctx_fugue, hash);
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, in1, size);
				sph_fugue512_close(&ctx_fugue, hash1);
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, in2, size);
				sph_fugue512_close(&ctx_fugue, hash2);
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, in3, size);
				sph_fugue512_close(&ctx_fugue, hash3);
				break;
		case SHABAL:
				//printf("SHAB,",i);
				if(size==80){
					intrlv_4x32( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x32_512(vhash, in, in1, in2, in3);
				}
				shabal512_4way_init(&ctx_shabal);
				shabal512_4way(&ctx_shabal, vhash, size);
				shabal512_4way_close(&ctx_shabal, vhash);
				dintrlv_4x32_512( hash, hash1, hash2, hash3, vhash);
				/*sph_shabal512_init(&ctx_shabal);
				sph_shabal512(&ctx_shabal, in, size);
				sph_shabal512_close(&ctx_shabal, hash);
				sph_shabal512_init(&ctx_shabal);
				sph_shabal512(&ctx_shabal, in1, size);
				sph_shabal512_close(&ctx_shabal, hash1);
				sph_shabal512_init(&ctx_shabal);
				sph_shabal512(&ctx_shabal, in2, size);
				sph_shabal512_close(&ctx_shabal, hash2);
				sph_shabal512_init(&ctx_shabal);
				sph_shabal512(&ctx_shabal, in3, size);
				sph_shabal512_close(&ctx_shabal, hash3);*/
				break;
		case WHIRLPOOL:
				//printf("WHIRL,",i);
				/*sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, in, size);
				sph_whirlpool_close(&ctx_whirlpool, hash);
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, in1, size);
				sph_whirlpool_close(&ctx_whirlpool, hash1);
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, in2, size);
				sph_whirlpool_close(&ctx_whirlpool, hash2);
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, in3, size);
				sph_whirlpool_close(&ctx_whirlpool, hash3);*/
				if(size==80){
					intrlv_4x64( vhash, in, in1, in2, in3, 640 );
				}else{
					intrlv_4x64_512(vhash, in, in1, in2, in3);
				}
				whirlpool_4way_init(&ctx_whirlpool);
				whirlpool_4way(&ctx_whirlpool, vhash, size);
				whirlpool_4way_close(&ctx_whirlpool, vhash);
				dintrlv_4x64_512( hash, hash1, hash2, hash3, vhash);
				break;
		}
		if(cnSelection >= 0) {
			memset(&hash[4], 0, 32);
			memset(&hash1[4], 0, 32);
			memset(&hash2[4], 0, 32);
			memset(&hash3[4], 0, 32);
		}
		in = (void*) hash;
		in1 = (void*) hash1;
		in2 = (void*) hash2;
		in3 = (void*) hash3;
		size = 64;

	}
	//intrlv_4x32(output, hash, hash1, hash2, hash3, 256);
	memcpy(output, hash, 32);
	memcpy(output1, hash1, 32);
	memcpy(output2, hash2, 32);
	memcpy(output3, hash3, 32);
	//printf("\n");
}


int scanhash_gr_4way( struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        uint32_t _ALIGN(64) endiandata[20];
		uint32_t _ALIGN(64) endiandata1[20];
		uint32_t _ALIGN(64) endiandata2[20];
		uint32_t _ALIGN(64) endiandata3[20];
		uint32_t _ALIGN(64) hash[8];
		uint32_t _ALIGN(64) hash1[8];
		uint32_t _ALIGN(64) hash2[8];
		uint32_t _ALIGN(64) hash3[8];
        const uint32_t first_nonce = pdata[19];
        uint32_t nonce = first_nonce;
        int thr_id = mythr->id;
        if (opt_benchmark)
			((uint32_t*)ptarget)[7] = 0x00ff;
        swab32_array( endiandata, pdata, 20 );
		swab32_array( endiandata1, pdata, 20 );
		swab32_array( endiandata2, pdata, 20 );
		swab32_array( endiandata3, pdata, 20 );
		if(hp_state == NULL)
			slow_hash_allocate_state();
        do {
			const uint32_t Htarg = ptarget[7];
			be32enc(&endiandata[19], nonce);
			be32enc(&endiandata1[19], nonce+1);
			be32enc(&endiandata2[19], nonce+2);
			be32enc(&endiandata3[19], nonce+3);
			gr_hash_4way(hash, hash1, hash2, hash3, endiandata, endiandata1, endiandata2, endiandata3);
				if (hash[7] <= Htarg) {
						pdata[19] = nonce;
						*hashes_done = pdata[19] - first_nonce;
						////printf("Hashrate %ld\n",pdata[19] - first_nonce);
						//submit_solution( work, hash, mythr);
						return 1;
				}
				if (hash1[7] <= Htarg) {
						pdata[19] = nonce+1;
						*hashes_done = pdata[19] - first_nonce;
						////printf("Hashrate %ld\n",pdata[19] - first_nonce);
						//submit_solution( work, hash1, mythr);
						return 1;
				}
				if (hash2[7] <= Htarg) {
						pdata[19] = nonce+2;
						*hashes_done = pdata[19] - first_nonce;
						////printf("Hashrate %ld\n",pdata[19] - first_nonce);
						//submit_solution( work, hash2, mythr);
						return 1;
				}
				if (hash3[7] <= Htarg) {
						pdata[19] = nonce+3;
						*hashes_done = pdata[19] - first_nonce;
						////printf("Hashrate %ld\n",pdata[19] - first_nonce);
						//submit_solution( work, hash3, mythr);
						return 1;
				}
				nonce=nonce+4;
			} while (nonce < max_nonce && !work_restart[thr_id].restart);
        pdata[19] = nonce;
        *hashes_done = pdata[19] - first_nonce + 1;
		slow_hash_free_state();
        return 0;
}
#endif
