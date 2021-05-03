#ifndef VIRTUAL_MEMORY_H_
#define VIRTUAL_MEMORY_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

bool InitHugePages(size_t threads);

void *AllocateLargePagesMemory(size_t size);

void *AllocateMemory(size_t size);

#endif // VIRTUAL_MEMORY_H_
