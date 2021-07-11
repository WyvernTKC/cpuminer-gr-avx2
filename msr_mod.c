#include "msr_mod.h"
#include "miner.h" // applog
#include <cpuid.h>
#include <fcntl.h> // flags
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // open, sleep

#define VENDOR_ID (0)
#define PROCESSOR_INFO (1)
#define EXTENDED_FEATURES (7)
#define PROCESSOR_EXT_INFO (0x80000001)
#define PROCESSOR_BRAND_STRING_1 (0x80000002)
#define PROCESSOR_BRAND_STRING_2 (0x80000003)
#define PROCESSOR_BRAND_STRING_3 (0x80000004)

#define EAX_Reg (0)
#define EBX_Reg (1)
#define ECX_Reg (2)
#define EDX_Reg (3)

static inline void cpuid(uint32_t level, int32_t output[4]) {
  memset(output, 0, sizeof(int32_t) * 4);

  __cpuid_count(level, 0, output[0], output[1], output[2], output[3]);
}

static inline int32_t get_masked(int32_t val, int32_t h, int32_t l) {
  val &= (0x7FFFFFFF >> (31 - (h - l))) << l;
  return val >> l;
}

enum MsrMod {
  MSR_MOD_NONE = 0,
  MSR_MOD_RYZEN_17H,
  MSR_MOD_RYZEN_19H,
  MSR_MOD_INTEL,
};

static inline uint32_t getMSR() {
  uint32_t msr_mod = 0;

  char vendor[13] = {0};
  int32_t data[4] = {0};

  cpuid(VENDOR_ID, data);

  memcpy(vendor + 0, &data[1], 4);
  memcpy(vendor + 4, &data[3], 4);
  memcpy(vendor + 8, &data[2], 4);

  cpuid(PROCESSOR_INFO, data);

  uint32_t proc_info = data[EAX_Reg];
  uint32_t family =
      get_masked(proc_info, 12, 8) + get_masked(proc_info, 28, 20);
  uint32_t model =
      (get_masked(proc_info, 20, 16) << 4) | get_masked(proc_info, 8, 4);

  if (memcmp(vendor, "AuthenticAMD", 12) == 0) {
    if (family >= 0x17) {

      switch (family) {
      case 0x17:
        applog(LOG_NOTICE, "MSR Ryzen v1");
        msr_mod = MSR_MOD_RYZEN_17H;
        switch (model) {
        case 1:
        case 17:
        case 32:
          applog(LOG_NOTICE, "Arch Zen");
          break;
        case 8:
        case 24:
          applog(LOG_NOTICE, "Arch Zen+");
          break;
        case 49:
        case 96:
        case 113:
        case 144:
          applog(LOG_NOTICE, "Arch Zen2");
          break;
        }
        break;

      case 0x19:
        msr_mod = MSR_MOD_RYZEN_19H;
        applog(LOG_NOTICE, "MSR Ryzen v2");
        applog(LOG_NOTICE, "Arch Zen3");
        break;

      default:
        applog(LOG_NOTICE, "MSR None");
        msr_mod = MSR_MOD_NONE;
        break;
      }
    }
  } else if (memcmp(vendor, "GenuineIntel", 12) == 0) {
    msr_mod = MSR_MOD_INTEL;
  }
  return msr_mod;
}

static inline uint64_t masked_value(uint64_t old_value, uint64_t new_value,
                                    uint64_t mask) {
  return (new_value & mask) | (old_value & ~mask);
}

#ifdef __MINGW32__
#include <winsock2.h>
#include <windows.h>

#define SERVICE_NAME L"WinRing0_1_2_0"
#define IOCTL_READ_MSR CTL_CODE(40000, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MSR CTL_CODE(40000, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)

const wchar_t *kServiceName = SERVICE_NAME;
HANDLE driver = INVALID_HANDLE_VALUE;
SC_HANDLE manager = NULL;
SC_HANDLE service = NULL;
bool reuse = false;

static bool uninstall() {
  if (driver != INVALID_HANDLE_VALUE) {
    CloseHandle(driver);
    usleep(100000);
  }

  if (!service) {
    return true;
  }

  bool result = true;

  if (!reuse) {
    SERVICE_STATUS serviceStatus;

    if (!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
      applog(LOG_ERR, "Failed to stop WinRing0 driver, error %u",
             GetLastError());
      result = false;
    }

    if (!DeleteService(service)) {
      applog(LOG_ERR, "Failed to remove WinRing0 driver, error %u",
             GetLastError());
      result = false;
    }
  }

  CloseServiceHandle(service);
  service = NULL;

  return result;
}

static bool init_msr() {
  DWORD err = 0;

  manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (!manager) {
    if ((err = GetLastError()) == ERROR_ACCESS_DENIED) {
      applog(LOG_ERR,
             "To access MSR register Administrator privileges are required.");
    } else {
      applog(LOG_ERR, "Failed to open service control manager, error %u", err);
    }
    return false;
  }

  wchar_t dir[1024];

  GetModuleFileNameW(NULL, dir, 1024);
  err = GetLastError();

  if (err != ERROR_SUCCESS) {
    applog(LOG_ERR, "Failed to get path to driver, error %u", err);
    return false;
  }

  for (int it = 1024 - 1; it != 0; --it) {
    if ((dir[it] == L'\\') || (dir[it] == L'/')) {
      ++it;
      dir[it] = L'\0';
      break;
    }
  }

  wcsncat(dir, L"WinRing0x64.sys", 15);

  service = OpenServiceW(manager, kServiceName, SERVICE_ALL_ACCESS);
  if (service) {
    applog(LOG_BLUE, "service WinRing0_1_2_0 already exists");

    SERVICE_STATUS status;
    const BOOL rc = QueryServiceStatus(service, &status);

    if (rc) {
      DWORD dwBytesNeeded = 0;

      QueryServiceConfigA(service, NULL, 0, &dwBytesNeeded);
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        BYTE *buffer = (BYTE *)alloca(dwBytesNeeded);
        LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)(buffer);

        if (QueryServiceConfigA(service, config, dwBytesNeeded,
                                &dwBytesNeeded)) {
          if (opt_debug) {
            applog(LOG_DEBUG, "service path: %s", config->lpBinaryPathName);
          }
        }
      }
    }

    if (rc && status.dwCurrentState == SERVICE_RUNNING) {
      if (opt_debug) {
        applog(LOG_DEBUG, "Reusing WinRing0_1_2_0");
      }
      reuse = true;
    } else if (!uninstall()) {
      applog(LOG_ERR, "Failed to uninstall the service.");
      return false;
    }
  }

  if (!reuse) {
    service =
        CreateServiceW(manager, kServiceName, kServiceName, SERVICE_ALL_ACCESS,
                       SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                       SERVICE_ERROR_NORMAL, dir, NULL, NULL, NULL, NULL, NULL);
    if (!service) {
      applog(LOG_ERR, "Failed to install WinRing0 driver, error %u",
             GetLastError());
      return false;
    }

    if (!StartService(service, 0, NULL)) {
      err = GetLastError();
      if (err != ERROR_SERVICE_ALREADY_RUNNING) {
        if (err == ERROR_FILE_NOT_FOUND) {
          applog(LOG_ERR,
                 "Failed to start WinRing0 driver: WinRing0x64.sys not found");
        } else {
          applog(LOG_ERR, "failed to start WinRing0 driver, error %u", err);
        }

        uninstall();
        return false;
      }
    }
  }

  driver = CreateFileW(L"\\\\.\\" SERVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (driver == INVALID_HANDLE_VALUE) {
    applog(LOG_ERR, "Failed to connect to WinRing0 driver, error %u",
           GetLastError());
    return false;
  }
  return true;
}

static bool rdmsr(uint32_t reg, int32_t cpu, uint64_t *value) {
  DWORD size = 0;
  return DeviceIoControl(driver, IOCTL_READ_MSR, &reg, sizeof(reg), &value,
                         sizeof(value), &size, NULL) != 0;
}

static bool wrmsr(uint32_t reg, uint64_t value, int32_t cpu) {
  struct {
    uint32_t reg;
    uint32_t value[2];
  } input;

  input.reg = reg;
  *((uint64_t *)(&input.value)) = value;

  DWORD output;
  DWORD k;
  return DeviceIoControl(driver, IOCTL_WRITE_MSR, &input, sizeof(input),
                         &output, sizeof(output), &k, NULL) != 0;
}

#else

static bool init_msr() {
  if (system("/sbin/modprobe msr allow_writes=on > /dev/null 2>&1") != 0) {
    applog(LOG_ERR, "msr kernel module is not available");
    return false;
  }
  return true;
}

static int msr_open(int32_t cpu, int flags) {
  char path[100];
  sprintf(path, "/dev/cpu/%d/msr", cpu);
  return open(path, flags);
}

static bool rdmsr(uint32_t reg, int32_t cpu, uint64_t *value) {
  int fd = msr_open(cpu, O_RDONLY);
  if (fd < 0) {
    return false;
  }
  const bool success = pread(fd, &value, sizeof(value), reg) == sizeof(value);
  close(fd);
  return success;
}

static bool wrmsr(uint32_t reg, uint64_t value, int32_t cpu) {
  int fd = msr_open(cpu, O_WRONLY);
  if (fd < 0) {
    return false;
  }
  const bool success = pwrite(fd, &value, sizeof(value), reg) == sizeof(value);
  close(fd);
  return success;
}

#endif

bool msr_write(uint32_t reg, uint64_t value, int32_t cpu, uint64_t mask) {
  // Check if there is a mask.
  if (mask != UINT64_MAX) {
    uint64_t old_val;
    if (rdmsr(reg, cpu, &old_val)) {
      value = masked_value(old_val, value, mask);
    } else {
      applog(LOG_ERR, "Cannot read MSR 0x%08X on cpu %d", reg, cpu);
      return false;
    }
  }

  // Write MSR to the core.
  const bool result = wrmsr(reg, value, cpu);
  if (!result) {
    applog(LOG_ERR, "Cannot set MSR 0x%08X to 0x%016X on cpu %d", reg, value,
           cpu);
  }
  return result;
}

bool execute_msr(int threads) {
  enum MsrMod msr_mod = getMSR();

  if (!init_msr()) {
#ifdef __MINGW32__
    // It can fail once on uninstall in Windows even with proper driver.
    // Should succeed after that.
    applog(LOG_NOTICE, "MSR init retry.");
    if (!init_msr()) {
      return false;
    }
#else
    return false;
#endif
  }

  size_t presets_num = 0;
  struct msr_data *presets;
  switch (msr_mod) {
  case MSR_MOD_INTEL:
    // Intel
    // 0x1a4:0xf
    presets_num = 1;
    presets = alloca(sizeof(struct msr_data) * presets_num);
    presets[0] = (struct msr_data){0x1a4, 0xF, UINT64_MAX};
    break;
  case MSR_MOD_RYZEN_19H:
    // AMD Ryzen (Zen3)
    // 0xc0011020:0x4480000000000
    // 0xc0011021:0x1c000200000040:0xffffffffffffffdf
    // 0xc0011022:0xc000000401500000
    // 0xc001102b:0x2000cc14
    presets_num = 4;
    presets = alloca(sizeof(struct msr_data) * presets_num);
    presets[0] = (struct msr_data){0xc0011020, 0x4480000000000, UINT64_MAX};
    presets[1] =
        (struct msr_data){0xc0011021, 0x1c000200000040, 0xffffffffffffffdf};
    presets[2] = (struct msr_data){0xc0011022, 0xc000000401500000, UINT64_MAX};
    presets[3] = (struct msr_data){0xc001102b, 0x2000cc14, UINT64_MAX};
    break;
  case MSR_MOD_RYZEN_17H:
    // AMD Ryzen (Zen1/Zen2)
    // 0xc0011020:0x0
    // 0xc0011021:0x40:0xffffffffffffffdf
    // 0xc0011022:0x1510000
    // 0xc001102b:0x2000cc16
    presets_num = 4;
    presets = alloca(sizeof(struct msr_data) * presets_num);
    presets[0] = (struct msr_data){0xc0011020, 0x0, UINT64_MAX};
    presets[1] = (struct msr_data){0xc0011021, 0x40, 0xffffffffffffffdf};
    presets[2] = (struct msr_data){0xc0011022, 0x1510000, UINT64_MAX};
    presets[3] = (struct msr_data){0xc001102b, 0x2000cc16, UINT64_MAX};
    break;
  case MSR_MOD_NONE:
    applog(LOG_NOTICE, "Unrecognised CPU, skipping MSR setup.");
    return false;
    break;
  };

  for (int thrid = 0; thrid < threads; thrid++) {
    for (size_t i = 0; i < presets_num; i++) {
      if (!msr_write(presets[i].reg, presets[i].value, thrid,
                     presets[i].mask)) {
        return false;
      }
    }
  }
  return true;
}
