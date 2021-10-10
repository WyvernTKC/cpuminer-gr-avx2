#include "msr_mod.h"
#include "miner.h" // applog
#include <cpuid.h>
#include <fcntl.h> // flags
#include <fstream>
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

class Msr {
public:
  Msr(bool print_err);
  ~Msr();

  bool msr_write(uint32_t reg, uint64_t value, int32_t cpu, uint64_t mask);
  bool is_available();

private:
  bool rdmsr(uint32_t reg, int32_t cpu, uint64_t *value);
  bool wrmsr(uint32_t reg, uint64_t value, int32_t cpu);
  bool initialized = false;

#ifdef __MINGW32__
  bool uninstall(bool);

  bool reuse = false;
  HANDLE driver = INVALID_HANDLE_VALUE;
  SC_HANDLE manager = nullptr;
  SC_HANDLE service = nullptr;
#endif
};

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

static inline MsrMod getMSR() {
  MsrMod msr_mod = MSR_MOD_NONE;

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
        if (opt_debug) {
          applog(LOG_NOTICE, "MSR Ryzen v1");
        }
        msr_mod = MSR_MOD_RYZEN_17H;
        switch (model) {
        case 1:
        case 17:
        case 32:
          if (opt_debug) {
            applog(LOG_NOTICE, "Arch Zen");
          }
          break;
        case 8:
        case 24:
          if (opt_debug) {
            applog(LOG_NOTICE, "Arch Zen+");
          }
          break;
        case 49:
        case 96:
        case 113:
        case 144:
          if (opt_debug) {
            applog(LOG_NOTICE, "Arch Zen2");
          }
          break;
        }
        break;

      case 0x19:
        msr_mod = MSR_MOD_RYZEN_19H;
        if (opt_debug) {
          applog(LOG_NOTICE, "MSR Ryzen v2");
          applog(LOG_NOTICE, "Arch Zen3");
        }
        break;

      default:
        if (opt_debug) {
          applog(LOG_NOTICE, "MSR None");
        }
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
#include <string>
#include <vector>
#include <winsock2.h>

#include <windows.h>

#define SERVICE_NAME L"WinRing0_1_2_0"
#define IOCTL_READ_MSR CTL_CODE(40000, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MSR CTL_CODE(40000, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)

static const wchar_t *kServiceName = SERVICE_NAME;

bool Msr::uninstall(bool print_err) {
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

    usleep(100000);
    if (!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
      if (print_err) {
        applog(LOG_ERR, "Failed to stop WinRing0 driver, error %u",
               GetLastError());
      }
      result = false;
    }
    usleep(100000);

    if (!DeleteService(service)) {
      if (print_err) {
        applog(LOG_ERR, "Failed to remove WinRing0 driver, error %u",
               GetLastError());
      }
      result = false;
    }
  }

  usleep(100000);
  CloseServiceHandle(service);
  service = nullptr;

  return result;
}

Msr::Msr(bool print_err) {
  DWORD err = 0;

  manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  usleep(100000);
  if (!manager) {
    if ((err = GetLastError()) == ERROR_ACCESS_DENIED && print_err) {
      applog(LOG_ERR,
             "To access MSR register Administrator privileges are required.");
    } else if (print_err) {
      applog(LOG_ERR, "Failed to open service control manager, error %u", err);
    }
    return;
  }

  std::vector<wchar_t> dir;

  do {
    dir.resize(dir.empty() ? MAX_PATH : dir.size() * 2);
    GetModuleFileNameW(nullptr, dir.data(), dir.size());
    err = GetLastError();
  } while (err == ERROR_INSUFFICIENT_BUFFER);

  if (err != ERROR_SUCCESS) {
    if (print_err) {
      applog(LOG_ERR, "Failed to get path to driver, error %u", err);
    }
    return;
  }

  for (auto it = dir.end() - 1; it != dir.begin(); --it) {
    if ((*it == L'\\') || (*it == L'/')) {
      ++it;
      *it = L'\0';
      break;
    }
  }

  const std::wstring driver_path =
      std::wstring(dir.data()) + L"WinRing0x64.sys";

  usleep(100000);
  service = OpenServiceW(manager, kServiceName, SERVICE_ALL_ACCESS);
  if (service) {
    if (opt_debug) {
      applog(LOG_BLUE, "service WinRing0_1_2_0 already exists");
    }

    SERVICE_STATUS status;
    usleep(100000);
    const auto rc = QueryServiceStatus(service, &status);

    if (rc) {
      DWORD dwBytesNeeded = 0;

      usleep(100000);
      QueryServiceConfigA(service, nullptr, 0, &dwBytesNeeded);
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buffer(dwBytesNeeded);
        auto config = reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(buffer.data());

        usleep(100000);
        if (QueryServiceConfigA(service, config, buffer.size(),
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
    } else if (!uninstall(print_err)) {
      if (print_err) {
        applog(LOG_ERR, "Failed to uninstall the service.");
      }
      return;
    }
  }

  if (!reuse) {
    usleep(100000);
    service = CreateServiceW(
        manager, kServiceName, kServiceName, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        driver_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!service) {
      if (print_err) {
        applog(LOG_ERR, "Failed to install WinRing0 driver, error %u",
               GetLastError());
      }
      return;
    }

    usleep(100000);
    if (!StartService(service, 0, nullptr)) {
      err = GetLastError();
      if (err != ERROR_SERVICE_ALREADY_RUNNING) {
        if (err == ERROR_FILE_NOT_FOUND && print_err) {
          applog(LOG_ERR,
                 "Failed to start WinRing0 driver: WinRing0x64.sys not found");
        } else if (print_err) {
          applog(LOG_ERR, "failed to start WinRing0 driver, error %u", err);
        }

        usleep(100000);
        uninstall(print_err);
        return;
      }
    }
  }

  usleep(100000);
  driver = CreateFileW(L"\\\\.\\" SERVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0,
                       nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (driver == INVALID_HANDLE_VALUE) {
    if (print_err) {
      applog(LOG_ERR, "Failed to connect to WinRing0 driver, error %u",
             GetLastError());
    }
    return;
  }
  initialized = true;
}

Msr::~Msr() { uninstall(false); }

bool Msr::rdmsr(uint32_t reg, int32_t cpu, uint64_t *value) {
  DWORD size = 0;
  return DeviceIoControl(driver, IOCTL_READ_MSR, &reg, sizeof(reg), &value,
                         sizeof(value), &size, nullptr) != 0;
}

bool Msr::wrmsr(uint32_t reg, uint64_t value, int32_t cpu) {
  struct {
    uint32_t reg;
    uint32_t value[2];
  } input;

  input.reg = reg;
  *((uint64_t *)(input.value)) = value;

  DWORD output;
  DWORD k;
  return DeviceIoControl(driver, IOCTL_WRITE_MSR, &input, sizeof(input),
                         &output, sizeof(output), &k, nullptr) != 0;
}

#else

Msr::Msr(bool print_err __attribute__((unused))) {
  bool mod_probe = true;
  if (system("/sbin/modprobe msr allow_writes=on > /dev/null 2>&1") != 0) {
    mod_probe = false;
  }
  std::ofstream file("/sys/module/msr/parameters/allow_writes",
                     std::ios::out | std::ios::binary | std::ios::trunc);
  if (file.is_open()) {
    file << "on";
  }
  bool allow_writes = false;
  if (file.good()) {
    allow_writes = true;
  }

  initialized = allow_writes || mod_probe;
  if (!initialized) {
    if (!mod_probe) {
      applog(LOG_ERR, "MSR kernel module is not available.");
    }
    if (!allow_writes) {
      applog(LOG_ERR, "Could not allow writes to MSR module.");
    }
    applog(LOG_ERR, "Consider running the miner as 'root' to enable MSR.");
  }
}

Msr::~Msr() = default;

static int msr_open(int32_t cpu, int flags) {
  char path[100];
  sprintf(path, "/dev/cpu/%d/msr", cpu);
  return open(path, flags);
}

bool Msr::rdmsr(uint32_t reg, int32_t cpu, uint64_t *value) {
  int fd = msr_open(cpu, O_RDONLY);
  if (fd < 0) {
    return false;
  }
  const bool success = pread(fd, &value, sizeof(value), reg) == sizeof(value);
  close(fd);
  return success;
}

bool Msr::wrmsr(uint32_t reg, uint64_t value, int32_t cpu) {
  int fd = msr_open(cpu, O_WRONLY);
  if (fd < 0) {
    return false;
  }
  const bool success = pwrite(fd, &value, sizeof(value), reg) == sizeof(value);
  close(fd);
  return success;
}

#endif

bool Msr::is_available() { return initialized; }

bool Msr::msr_write(uint32_t reg, uint64_t value, int32_t cpu, uint64_t mask) {
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

int enable_msr(int threads) {
  enum MsrMod msr_mod = getMSR();

  // Do not even initialize MSR if we do not have MSR mod for the CPU
  if (msr_mod == MsrMod::MSR_MOD_NONE) {
    return 2;
  }
  static Msr msr = Msr(false);
  if (!msr.is_available()) {
#ifdef __MINGW32__
    // Retry at least once on Windows. It can be stubborn while uninstalling
    // the driver for some reason.
    msr = Msr(true);
    if (!msr.is_available()) {
      return 1;
    }
#else
    return 1;
#endif
  }

  size_t presets_num = 0;
  struct msr_data *presets;
  switch (msr_mod) {
  case MSR_MOD_INTEL:
    // Intel
    // 0x1A4:0xF
    presets_num = 1;
    presets = (msr_data *)alloca(sizeof(struct msr_data) * presets_num);
    presets[0] = (struct msr_data){0x1A4, 0xF, UINT64_MAX};
    break;
  case MSR_MOD_RYZEN_19H:
    // AMD Ryzen (Zen3)
    // 0xc0011020:0x4480000000000
    // 0xc0011021:0x1C000200000040
    // 0xc0011022:0xC000000401500000
    // 0xc001102B:0x2000CC14
    presets_num = 4;
    presets = (msr_data *)alloca(sizeof(struct msr_data) * presets_num);
    presets[0] = (struct msr_data){0xC0011020, 0x4480000000000, UINT64_MAX};
    presets[1] = (struct msr_data){0xC0011021, 0x1c000200000040, UINT64_MAX};
    presets[2] = (struct msr_data){0xC0011022, 0xC000000401500000, UINT64_MAX};
    presets[3] = (struct msr_data){0xC001102B, 0x2000CC14, UINT64_MAX};
    break;
  case MSR_MOD_RYZEN_17H:
    // AMD Ryzen (Zen1/Zen1+/Zen2)
    // 0xc0011020:0x0
    // 0xc0011021:0x40
    // 0xc0011022:0x1510000
    // 0xc001102B:0x2000CC16
    presets_num = 4;
    presets = (msr_data *)alloca(sizeof(struct msr_data) * presets_num);
    presets[0] = (struct msr_data){0xC0011020, 0x0, UINT64_MAX};
    presets[1] = (struct msr_data){0xC0011021, 0x40, UINT64_MAX};
    presets[2] = (struct msr_data){0xC0011022, 0x1510000, UINT64_MAX};
    presets[3] = (struct msr_data){0xC001102B, 0x2000CC16, UINT64_MAX};
    break;
  case MSR_MOD_NONE:
    // Redundant as check is above.
    return 2;
    break;
  };

  for (int thrid = 0; thrid < threads; thrid++) {
    for (size_t i = 0; i < presets_num; i++) {
      if (!msr.msr_write(presets[i].reg, presets[i].value, thrid,
                         presets[i].mask)) {
        return 1;
      }
    }
  }
  return 0;
}
