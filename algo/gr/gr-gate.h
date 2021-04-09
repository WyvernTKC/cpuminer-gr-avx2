#ifndef GR_GATE_H__
#define GE_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

void gr_hash( void *state, const void *input );
void gr_hash_4way(void* output, void* output1, void* output2, void* output3, const void* input, const void* input1, const void* input2, const void* input3);
//void gr_hash_4way( void *state, const void *input );
int scanhash_gr(struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr);
int scanhash_gr_4way(struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr);

#endif
