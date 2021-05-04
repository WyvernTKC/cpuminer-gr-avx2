#ifndef VIRTUAL_MEMORY_H_
#define VIRTUAL_MEMORY_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

static bool huge_pages = false;

bool InitHugePages(size_t threads);

void *AllocateLargePagesMemory(size_t size);

void *AllocateMemory(size_t size);

#endif // VIRTUAL_MEMORY_H_
