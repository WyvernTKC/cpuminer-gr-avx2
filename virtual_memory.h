#ifndef VIRTUAL_MEMORY_H_
#define VIRTUAL_MEMORY_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Store allocation method and size.
extern __thread bool allocated_hp;
extern __thread size_t currently_allocated;

bool InitHugePages(size_t threads, size_t max_large_pages);

void *AllocateLargePagesMemory(size_t size);
void DeallocateLargePagesMemory(void **memory);

void *AllocateMemory(size_t size);

void DeallocateMemory(void **memory);

void PrepareMemory(void **memory, size_t size);

#ifdef __cplusplus
}
#endif

#endif // VIRTUAL_MEMORY_H_
