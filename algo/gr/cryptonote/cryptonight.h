#ifndef CRYPTONIGHT_H
#define CRYPTONIGHT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define INIT_SIZE_BLK 8
#define INIT_SIZE_BYTE 128

void cryptonight_hash(const char *input, char *output, const uint32_t memory,
                      const uint32_t iterations, const uint32_t mask);

// Helper functions for different types of Cryptonight variants.
void cryptonight_dark_hash(const char *input, char *output);
void cryptonight_darklite_hash(const char *input, char *output);
void cryptonight_fast_hash(const char *input, char *output);
void cryptonight_lite_hash(const char *input, char *output);
void cryptonight_turtle_hash(const char *input, char *output);
void cryptonight_turtlelite_hash(const char *input, char *output);

#if defined(__AVX2__)
#include "crypto/hash-ops.h"

#pragma pack(push, 1)
union cn_slow_hash_state {
  union hash_state hs;
  struct {
    uint8_t k[64];
    uint8_t init[INIT_SIZE_BYTE];
  };
};
#pragma pack(pop)

#pragma pack(push, 1)
struct cryptonight_ctx {
  union cn_slow_hash_state state;
  uint8_t text[INIT_SIZE_BYTE];
};
#pragma pack(pop)

void cryptonight_2way_hash(const char *input0, const char *input1,
                           char *output0, char *output1, const uint32_t memory,
                           const uint32_t iter_div, const uint32_t cn_aes_init);

// Helper functions for different types of Cryptonight variants.
void cryptonight_dark_2way_hash(const char *input0, const char *input1,
                                char *output0, char *output1);
void cryptonight_darklite_2way_hash(const char *input0, const char *input1,
                                    char *output0, char *output1);
void cryptonight_fast_2way_hash(const char *input0, const char *input1,
                                char *output0, char *output1);
void cryptonight_lite_2way_hash(const char *input0, const char *input1,
                                char *output0, char *output1);
void cryptonight_turtle_2way_hash(const char *input0, const char *input1,
                                  char *output0, char *output1);
void cryptonight_turtlelite_2way_hash(const char *input0, const char *input1,
                                      char *output0, char *output1);

#endif // __AVX2__ / 2way

#ifdef __cplusplus
}
#endif

#endif // CRYPTONIGHT_H
