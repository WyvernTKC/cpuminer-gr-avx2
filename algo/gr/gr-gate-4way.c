#include "gr-gate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../blake/sph_blake.h"
#include "../bmw/sph_bmw.h"
#include "../groestl/sph_groestl.h"
#include "../jh/sph_jh.h"
#include "../keccak/sph_keccak.h"
#include "../skein/sph_skein.h"
#include "../luffa/sph_luffa.h"
#include "../cubehash/sph_cubehash.h"
#include "../shavite/sph_shavite.h"
#include "../simd/sph_simd.h"
#include "../echo/sph_echo.h"
#include "../hamsi/sph_hamsi.h"
#include "../fugue/sph_fugue.h"
#include "../shabal/sph_shabal.h"
#include "../whirlpool/sph_whirlpool.h"
#include "../sha/sph_sha2.h"
#include "../tiger/sph_tiger.h"
#include "../lyra2/lyra2.h"
#include "../haval/sph-haval.h"
#include "../gost/sph_gost.h"
#include "../blake/blake-hash-4way.h"
#include "../bmw/bmw-hash-4way.h"
#include "../groestl/aes_ni/hash-groestl.h"
#include "../skein/skein-hash-4way.h"
#include "../jh/jh-hash-4way.h"
#include "../keccak/keccak-hash-4way.h"
#include "../luffa/luffa-hash-2way.h"
#include "../cubehash/cube-hash-2way.h"
#include "../shavite/shavite-hash-2way.h"
#include "../simd/simd-hash-2way.h"
#include "../echo/aes_ni/hash_api.h"
#include "../hamsi/hamsi-hash-4way.h"
#include "../fugue/sph_fugue.h"
#include "../shabal/shabal-hash-4way.h"
#include "../whirlpool/sph_whirlpool.h"
#include "../haval/haval-hash-4way.h"
#include "../sha/sha2-hash-4way.h"
#include "cryptonote/cryptonight_dark.h"
#include "cryptonote/cryptonight_dark_lite.h"
#include "cryptonote/cryptonight_fast.h"
#include "cryptonote/cryptonight.h"
#include "cryptonote/cryptonight_lite.h"
#include "cryptonote/cryptonight_soft_shell.h"
#include "cryptonote/cryptonight_turtle.h"
#include "cryptonote/cryptonight_turtle_lite.h"

int64_t gr_get_max64()
{
   return 0x7ffLL;
}

bool register_gr_algo( algo_gate_t* gate )
{
  gate->scanhash         = (void*)&scanhash_gr;
  gate->hash             = (void*)&gr_hash;
  gate->optimizations    = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->get_max64        = (void*)&gr_get_max64;
  gate->set_target       = (void*)&scrypt_set_target;
  return true;
};

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

	//uint32_t hash[64/4];
	uint64_t hash0[8] __attribute__ ((aligned (64)));
    	uint64_t hash1[8] __attribute__ ((aligned (64)));
    	uint64_t hash2[8] __attribute__ ((aligned (64)));
    	uint64_t hash3[8] __attribute__ ((aligned (64)));
    	uint64_t vhash[8*4] __attribute__ ((aligned (64)));
    	uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
    	uint64_t vhashB[8*4] __attribute__ ((aligned (64)));

	blake512_4way_context	ctx_blake;
	bmw512_4way_context	ctx_bmw;
	//hashState_groestl	ctx_groestl;
	sph_groestl512_context ctx_groestl;
	jh512_4way_context ctx_jh;
	keccak512_4way_context ctx_keccak;
	skein512_4way_context ctx_skein;
	luffa_2way_context ctx_luffa;
	cube_2way_context ctx_cubehash;
	shavite512_2way_context ctx_shavite;
	//simd_2way_context ctx_simd;
	//hashState_echo ctx_echo;
	sph_simd512_context ctx_simd;
	sph_echo512_context ctx_echo;
	hamsi512_4way_context ctx_hamsi;
	sph_fugue512_context ctx_fugue;
	shabal512_4way_context ctx_shabal;
	sph_whirlpool_context ctx_whirlpool;
	haval256_5_4way_context ctx_haval;
	sph_tiger_context ctx_tiger;
	sph_gost512_context ctx_gost;
	sph_sha256_context ctx_sha;
	//sha256_4way_context ctx_sha;

	void *in = (void*) input;
        intrlv_4x64_512( vhash, in, in, in, in );
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
			dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
			cryptonightdark_hash(hash0, hash0, size, 1);
			intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
			break;
		 case CNDarklite:
			dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
			cryptonightdarklite_hash(hash0, hash0, size, 1);
			intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
			break;
		 case CNFast:
			dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
			cryptonightfast_hash(hash0, hash0, size, 1);
			intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
			break;
		 case CNLite:
			dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
			cryptonightlite_hash(hash0, hash0, size, 1);
			intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
			break;
		 case CNTurtle:
			dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
			cryptonightturtle_hash(hash0, hash0, size, 1);
			intrlv_4x64_512( vhash, hash0, hash1, hash3, hash3 );
			break;
		 case CNTurtlelite:
			dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
			cryptonightturtlelite_hash(hash0, hash0, size, 1);
			intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
			break;
		}
		//selection core algo
		switch (algo) {
		case BLAKE:
				blake512_4way_init(&ctx_blake);
				blake512_4way(&ctx_blake, vhash, size);
				blake512_4way_close(&ctx_blake, vhash);
				break;
		case BMW:
				bmw512_4way_init(&ctx_bmw);
				bmw512_4way(&ctx_bmw, vhash, size);
				bmw512_4way_close(&ctx_bmw, vhash);
				break;
		case GROESTL:
				dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
				/*init_groestl(&ctx_groestl, size);
				update_and_final_groestl(&ctx_groestl, (char*)hash0, (char*)hash0, 512);//size??
				init_groestl(&ctx_groestl, size);
				update_and_final_groestl(&ctx_groestl, (char*)hash1, (char*)hash1, 512);//size??
				init_groestl(&ctx_groestl, size);
				update_and_final_groestl(&ctx_groestl, (char*)hash2, (char*)hash2, 512);//size??
				init_groestl(&ctx_groestl, size);
				update_and_final_groestl(&ctx_groestl, (char*)hash3, (char*)hash3, 512);//size??*/
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, hash0, size);
				sph_groestl512_close(&ctx_groestl, hash0);
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, hash1, size);
				sph_groestl512_close(&ctx_groestl, hash1);
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, hash2, size);
				sph_groestl512_close(&ctx_groestl, hash2);
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, hash3, size);
				sph_groestl512_close(&ctx_groestl, hash3);
				intrlv_4x64_512(vhash, hash0, hash1, hash2, hash3);
				break;
		case SKEIN:
				skein512_4way_init(&ctx_skein);
				skein512_4way(&ctx_skein, vhash, size);
				skein512_4way_close(&ctx_skein, vhash);
				break;
		case JH:
				jh512_4way_init(&ctx_jh);
				jh512_4way(&ctx_jh, vhash, size);
				jh512_4way_close(&ctx_jh, vhash);
				break;
		case KECCAK:
				keccak512_4way_init(&ctx_keccak);
				keccak512_4way(&ctx_keccak, vhash, size);
				keccak512_4way_close(&ctx_keccak, vhash);
				break;
		case LUFFA:
				rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
				luffa_2way_init(&ctx_luffa, 512);
				luffa_2way_update_close(&ctx_luffa, vhashA, vhashA, size);
				luffa_2way_init(&ctx_luffa, 512);
				luffa_2way_update_close(&ctx_luffa, vhashB, vhashB, size);
				dintrlv_2x128_512( hash0, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );
				intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
				break;
		case CUBEHASH:
				rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
				cube_2way_init(&ctx_cubehash, 512, 16, 32);
				cube_2way_update_close(&ctx_cubehash, vhashA, vhashA, size);
				cube_2way_init(&ctx_cubehash, 512, 16, 32);
				cube_2way_update_close(&ctx_cubehash, vhashB, vhashB, size);
				dintrlv_2x128_512( hash0, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );
				intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
				break;
		case SHAVITE:
				rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
				shavite512_2way_init(&ctx_shavite);
				shavite512_2way_update_close(&ctx_shavite, vhashA, vhashA, size);
				shavite512_2way_init(&ctx_shavite);
				shavite512_2way_update_close(&ctx_shavite, vhashB, vhashB, size);
				dintrlv_2x128_512( hash0, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );
				intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
				break;
		case SIMD:
				//rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
                                dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
				sph_simd512_init(&ctx_simd);
				sph_simd512(&ctx_simd, hash0, size);
				sph_simd512_close(&ctx_simd, hash0);
				sph_simd512_init(&ctx_simd);
				sph_simd512(&ctx_simd, hash1, size);
				sph_simd512_close(&ctx_simd, hash1);
				sph_simd512_init(&ctx_simd);
				sph_simd512(&ctx_simd, hash2, size);
				sph_simd512_close(&ctx_simd, hash2);
				sph_simd512_init(&ctx_simd);
				sph_simd512(&ctx_simd, hash3, size);
				sph_simd512_close(&ctx_simd, hash3);
				/*simd_2way_init(&ctx_simd, 512);
				simd_2way_update_close(&ctx_simd, vhashA, vhashA, size);//size??
				simd_2way_init(&ctx_simd, 512);
				simd_2way_update_close(&ctx_simd, vhashB, vhashB, size);//size??
				dintrlv_2x128_512( hash0, hash1, vhashA );
				dintrlv_2x128_512( hash2, hash3, vhashB );*/
				intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
				break;
		case ECHO:
				dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
				sph_echo512_init(&ctx_echo);
				sph_echo512(&ctx_echo, hash0, size);
				sph_echo512_close(&ctx_echo, hash0);
				sph_echo512_init(&ctx_echo);
				sph_echo512(&ctx_echo, hash1, size);
				sph_echo512_close(&ctx_echo, hash1);
				sph_echo512_init(&ctx_echo);
				sph_echo512(&ctx_echo, hash2, size);
				sph_echo512_close(&ctx_echo, hash2);
				sph_echo512_init(&ctx_echo);
				sph_echo512(&ctx_echo, hash3, size);
				sph_echo512_close(&ctx_echo, hash3);
				/*init_echo(&ctx_echo, 512);
				update_final_echo(&ctx_echo, (BitSequence *)hash0,(const BitSequence *) hash0, size );//size??
				init_echo(&ctx_echo, 512);
				update_final_echo(&ctx_echo, (BitSequence *)hash1,(const BitSequence *) hash1, size );//size??
				init_echo(&ctx_echo, 512);
				update_final_echo(&ctx_echo, (BitSequence *)hash2,(const BitSequence *) hash2, size );//size??
				init_echo(&ctx_echo, 512);
				update_final_echo(&ctx_echo, (BitSequence *)hash3,(const BitSequence *) hash3, size );//size??*/
				intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
				break;
		case HAMSI:
				hamsi512_4way_init(&ctx_hamsi);
				hamsi512_4way(&ctx_hamsi, vhash, size);
				hamsi512_4way_close(&ctx_hamsi, vhash);
				break;
		case FUGUE:
				dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, hash0, size);
				sph_fugue512_close(&ctx_fugue, hash0);
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, hash1, size);
				sph_fugue512_close(&ctx_fugue, hash1);
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, hash2, size);
				sph_fugue512_close(&ctx_fugue, hash2);
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, hash3, size);
				sph_fugue512_close(&ctx_fugue, hash3);
				intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
				break;
		case SHABAL:
				shabal512_4way_init(&ctx_shabal);
				shabal512_4way(&ctx_shabal, vhash, size);
				shabal512_4way_close(&ctx_shabal, vhash);
				break;
		case WHIRLPOOL:
				dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, hash0, size);
				sph_whirlpool_close(&ctx_whirlpool, hash0);
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, hash1, size);
				sph_whirlpool_close(&ctx_whirlpool, hash1);
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, hash2, size);
				sph_whirlpool_close(&ctx_whirlpool, hash2);
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, hash3, size);
				sph_whirlpool_close(&ctx_whirlpool, hash3);
				intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
				break;
		}
		dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
		if(cnSelection >= 0) {
			//printf("2\n");
			memset(&hash0[4], 0, 32);
			memset(&hash1[4], 0, 32);
			memset(&hash2[4], 0, 32);
			memset(&hash3[4], 0, 32);
			//printf("3\n");
		}
		//in = (void*) hash0;
		//hash1 = (void*) hash0;
		//hash2 = (void*) hash0;
		//hash3 = (void*) hash0;
		size = 64;
		intrlv_4x64_512( vhash, hash0, hash0, hash0, hash0 );
	}
	dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
	memcpy(output, hash0, 32);
}

int scanhash_gr( struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        uint32_t _ALIGN(64) endiandata[20];
        const uint32_t first_nonce = pdata[19];
        uint32_t nonce = first_nonce;
        int thr_id = mythr->id;

        if (opt_benchmark)
                ((uint32_t*)ptarget)[7] = 0x0000ff;

        swab32_array( endiandata, pdata, 20 );

        do {
                const uint32_t Htarg = ptarget[7];
                uint32_t hash[8];
                be32enc(&endiandata[19], nonce);
                gr_hash(hash, endiandata);

                if (hash[7] <= Htarg) {
                        pdata[19] = nonce;
                        *hashes_done = pdata[19] - first_nonce;
                        return 1;
                }
                nonce++;

        } while (nonce < max_nonce && !work_restart[thr_id].restart);

        pdata[19] = nonce;
        *hashes_done = pdata[19] - first_nonce + 1;
        return 0;
}
