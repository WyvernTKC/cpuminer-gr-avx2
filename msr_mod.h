#ifndef MSR_MOD_H_
#define MSR_MOD_H_

#include <stdbool.h>
#include <stdint.h>

struct msr_data {
  uint32_t reg;
  uint64_t value;
  uint64_t mask;
};

bool execute_msr(int threads);
bool msr_write(uint32_t reg, uint64_t value, int32_t cpu, uint64_t mask);

#endif // MSR_MOD_H
