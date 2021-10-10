/*
 * Copyright 2021 Delgon
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef CRYPTONIGHT_H_
#define CRYPTONIGHT_H_

#include <cstdint>

// Variant      MEMORY            ITERATIONS      MASK
// Turtlelite   256KiB*, 2^18     2^16            (MEMORY - 16) / 2
// Turtle       256KiB,  2^18     2^16            (MEMORY - 16)
// Darklite     512KiB*, 2^19     2^17            (MEMORY - 16) / 2
// Dark         512KiB,  2^19     2^17            (MEMORY - 16)
// Lite         1MiB,    2^20     2^18            (MEMORY - 16)
// Fast         2MiB,    2^21     2^18            (MEMORY - 16)
// Turtlelite / Darklite requires memory / 2 of their main variant but still
// needs to calculate the 2nd half, can be done in the end without use of the
// half of the required memory.

#define TURTLELITE 262144, 65536, 131056, 131200, 1024, 2048
#define TURTLE 262144, 65536, 262128, 262144, 1024, 2048
#define DARKLITE 524288, 131072, 262128, 262272, 1024, 2048
#define DARK 524288, 131072, 524272, 524288, 1024, 2048
#define LITE 1048576, 262144, 1048560, 1048576, 1024, 2048
#define FAST 2097152, 262144, 2097136, 2097152, 1024, 2048

template <size_t kMemory, size_t kIterations, uint32_t kMask, size_t kShift,
          size_t kPrefetchW, size_t kPrefetchR, bool kL1Prefetch>
void cryptonight_hash(const void *input0, void *output0);

template <size_t kMemory, size_t kIterations, uint32_t kMask, size_t kShift,
          size_t kPrefetchW, size_t kPrefetchR, bool kL1Prefetch>
void cryptonight_2way_hash(const void *input0, const void *input1,
                           void *output0, void *output1);
#ifdef __AVX2__

template <size_t kMemory, size_t kIterations, uint32_t kMask, size_t kShift,
          size_t kPrefetchW, size_t kPrefetchR, bool kL1Prefetch>
void cryptonight_4way_hash(const void *input0, const void *input1,
                           const void *input2, const void *input3,
                           void *output0, void *output1, void *output2,
                           void *output3);

#endif // AVX2

// Actual implementation of the template functions.
#include "cryptonight.h_inline"

#endif // CRYPTONIGHT_H_
