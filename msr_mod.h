#ifndef MSR_MOD_H_
#define MSR_MOD_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct msr_data {
  uint32_t reg;
  uint64_t value;
  uint64_t mask;
};

int enable_msr(int threads);

#ifdef __cplusplus
}
#endif

#endif // MSR_MOD_H
