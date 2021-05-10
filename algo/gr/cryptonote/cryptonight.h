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

void cryptonight_hash(const void *input, void *output, const uint32_t memory,
                      const uint32_t iterations, const uint32_t mask);

// Helper functions for different types of Cryptonight variants.
void cryptonight_dark_hash(const void *input, void *output);
void cryptonight_darklite_hash(const void *input, void *output);
void cryptonight_fast_hash(const void *input, void *output);
void cryptonight_lite_hash(const void *input, void *output);
void cryptonight_turtle_hash(const void *input, void *output);
void cryptonight_turtlelite_hash(const void *input, void *output);

#if defined(__AVX2__)

void cryptonight_2way_hash(const void *input0, const void *input1,
                           void *output0, void *output1, const uint32_t memory,
                           const uint32_t iterations, const uint32_t mask);

// Helper functions for different types of Cryptonight variants.
void cryptonight_dark_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1);
void cryptonight_darklite_2way_hash(const void *input0, const void *input1,
                                    void *output0, void *output1);
void cryptonight_fast_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1);
void cryptonight_lite_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1);
void cryptonight_turtle_2way_hash(const void *input0, const void *input1,
                                  void *output0, void *output1);
void cryptonight_turtlelite_2way_hash(const void *input0, const void *input1,
                                      void *output0, void *output1);
#endif // __AVX2__ / 2way

#ifdef __cplusplus
}
#endif

#endif // CRYPTONIGHT_H
