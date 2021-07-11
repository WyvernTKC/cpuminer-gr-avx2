/* $Id: sph_blake.h 252 2011-06-07 17:55:14Z tp $ */
/**
 * BLAKE interface. BLAKE is a family of functions which differ by their
 * output size; this implementation defines BLAKE for output sizes 224,
 * 256, 384 and 512 bits. This implementation conforms to the "third
 * round" specification.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_blake.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef __BLAKE_HASH_4WAY__
#define __BLAKE_HASH_4WAY__ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "algo/sha/sph_types.h"
#include "simd-utils.h"
#include <stddef.h>

#define SPH_SIZE_blake512 512

#ifdef __AVX2__

// Blake-512 4 way AVX2

typedef struct {
  __m256i buf[16];
  __m256i H[8];
  __m256i S[4];
  size_t ptr;
  sph_u64 T0, T1;
} blake_4way_big_context __attribute__((aligned(128)));

typedef blake_4way_big_context blake512_4way_context;

void blake512_4way_init(blake_4way_big_context *sc);
void blake512_4way_update(void *cc, const void *data, size_t len);
void blake512_4way_close(void *cc, void *dst);
void blake512_4way_full(blake_4way_big_context *sc, void *dst, const void *data,
                        size_t len);

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) &&  \
    defined(__AVX512BW__)

////////////////////////////
//
//// Blake-512 8 way AVX512

typedef struct {
  __m512i buf[16];
  __m512i H[8];
  __m512i S[4];
  size_t ptr;
  sph_u64 T0, T1;
} blake_8way_big_context __attribute__((aligned(128)));

typedef blake_8way_big_context blake512_8way_context;

void blake512_8way_init(blake_8way_big_context *sc);
void blake512_8way_update(void *cc, const void *data, size_t len);
void blake512_8way_close(void *cc, void *dst);
void blake512_8way_full(blake_8way_big_context *sc, void *dst, const void *data,
                        size_t len);

#endif // AVX512
#endif // AVX2

#ifdef __cplusplus
}
#endif

#endif // BLAKE_HASH_4WAY_H__
