#include "virtual_memory.h"
#include "miner.h" // applog
#include <math.h>  // ceil
#include <stdio.h>
#include <unistd.h> // usleep

static bool huge_pages = false;
__thread bool allocated_hp = false;
__thread size_t currently_allocated = 0;

// Large Page size should be a multiple of 2MiB.
static inline size_t GetProperSize(size_t size) {
  return (size_t)ceil((double)size / 2097152.) * 2097152;
}

#ifdef __MINGW32__
// Windows
#ifndef UNICODE
#define UNICODE
#endif // UNICODE

#ifndef _UNICODE
#define _UNICODE
#endif // _UNICODE

#include <ntsecapi.h>
#include <ntstatus.h>
#include <tchar.h>
#include <winsock2.h>

#include <windows.h>
/*****************************************************************
SetLockPagesPrivilege: a function to obtain or
release the privilege of locking physical pages.
Inputs:
HANDLE hProcess: Handle for the process for which the
privilege is needed
BOOL bEnable: Enable (TRUE) or disable?
Return value: TRUE indicates success, FALSE failure.
*****************************************************************/
/**
 * AWE Example:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa366531(v=vs.85).aspx
 * Creating a File Mapping Using Large Pages:
 * https://msdn.microsoft.com/en-us/library/aa366543(VS.85).aspx
 */
static BOOL SetLockPagesPrivilege() {
  HANDLE token;

  if (OpenProcessToken(GetCurrentProcess(),
                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) != TRUE) {
    if (opt_debug) {
      applog(LOG_DEBUG, "Huge Pages: Failed to open process token.");
    }
    return FALSE;
  }

  TOKEN_PRIVILEGES tp;
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME,
                            &(tp.Privileges[0].Luid))) {
    if (opt_debug) {
      applog(LOG_DEBUG, "Huge Pages: Failed to lookup privilege table.");
    }
    return FALSE;
  }

  BOOL rc = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
  if (!rc || GetLastError() != ERROR_SUCCESS) {
    if (opt_debug) {
      applog(LOG_DEBUG, "Huge Pages: Failed to adjust privelege token.");
    }
    return FALSE;
  }

  CloseHandle(token);

  return TRUE;
}

static void StringToLsaUnicodeString(PLSA_UNICODE_STRING lsaString,
                                     LPWSTR string) {
  const DWORD dwLen = (DWORD)wcslen(string);
  lsaString->Buffer = (LPWSTR)string;
  lsaString->Length = (USHORT)((dwLen) * sizeof(WCHAR));
  lsaString->MaximumLength = (USHORT)((dwLen + 1) * sizeof(WCHAR));
}

NTSTATUS OpenPolicy(LPWSTR name, DWORD access, PLSA_HANDLE policy_handle) {
  LSA_OBJECT_ATTRIBUTES attributes;
  ZeroMemory(&attributes, sizeof(attributes));
  LSA_UNICODE_STRING pc_str;
  PLSA_UNICODE_STRING pc = NULL;

  if (name != NULL) {
    StringToLsaUnicodeString(&pc_str, name);
    pc = &pc_str;
  }

  return LsaOpenPolicy(pc, &attributes, access, policy_handle);
}

NTSTATUS SetPrivilege(LSA_HANDLE policy_handle, PSID account_sid,
                      LPWSTR privilege_name) {
  LSA_UNICODE_STRING priv_string;
  StringToLsaUnicodeString(&priv_string, privilege_name);

  return LsaAddAccountRights(policy_handle, account_sid, &priv_string, 1);
}

static BOOL ObtainLockPagesPrivilege() {
  HANDLE token;
  PTOKEN_USER user = NULL;

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    DWORD size = 0;

    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size) {
      user = (PTOKEN_USER)malloc(size);
    }

    GetTokenInformation(token, TokenUser, user, size, &size);
    CloseHandle(token);
  }

  if (!user) {
    applog(LOG_ERR, "Huge Pages: Failed token query.");
    return FALSE;
  }

  NTSTATUS status;
  BOOL result = FALSE;
  LSA_HANDLE handle;
  if ((status = OpenPolicy(NULL, POLICY_ALL_ACCESS, &handle))) {
    applog(LOG_ERR, "Huge Pages: Failed to open policy %u",
           LsaNtStatusToWinError(status));
  }

  if ((status =
           SetPrivilege(handle, user->User.Sid, _T(SE_LOCK_MEMORY_NAME)))) {
    applog(LOG_ERR, "Huge pages: Failed to add account rights %lu",
           LsaNtStatusToWinError(status));
    result = FALSE;
  } else {
    applog(LOG_WARNING,
           "Huge pages support was successfully enabled, but system reboot "
           "is required to use it!");
    sleep(5);
    result = TRUE;
  }

  free(user);
  return result;
}

static BOOL TrySetLockPagesPrivilege() {
  if (SetLockPagesPrivilege()) {
    return TRUE;
  }
  return ObtainLockPagesPrivilege() && SetLockPagesPrivilege();
}

bool InitHugePages(size_t threads, size_t max_large_pages) {
  huge_pages = TrySetLockPagesPrivilege();
  return huge_pages;
}

void *AllocateLargePagesMemory(size_t size) {
  const size_t min = GetLargePageMinimum();
  void *mem = NULL;
  if (min > 0) {
    mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
                       PAGE_READWRITE);
  } else {
    mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  }
  return mem;
}

void DeallocateLargePagesMemory(void **memory) {
  VirtualFree(*memory, 0, MEM_RELEASE);
  *memory = NULL;
  allocated_hp = false;
}

#else
// Linux
#include <numa.h> // numa_max_node
#include <sys/mman.h>

// Should fix compile errors on some older kernels and systems.
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

static inline int read_hp(const char *path) {
  FILE *fd;
  fd = fopen(path, "r");
  if (fd == NULL) {
    return -1;
  }

  uint64_t value = 0;
  int read = fscanf(fd, "%lu", &value);
  if (ferror(fd) != 0 || read != 1) {
    fclose(fd);
    return -2;
  }
  fclose(fd);
  return (int)value;
}

static inline bool write_hp(const char *path, uint64_t value) {
  FILE *fd;
  fd = fopen(path, "w");
  if (fd == NULL) {
    return false;
  }

  int wrote = fprintf(fd, "%lu", value);
  if (ferror(fd) != 0 && wrote != 1) {
    fclose(fd);
    return false;
  }
  fclose(fd);
  return true;
}

static bool InitNodeHugePages(size_t threads, size_t node) {
  char free_path[256];
  sprintf(free_path,
          "/sys/devices/system/node/node%lu/hugepages/"
          "hugepages-2048kB/free_hugepages",
          node);
  int available_pages = read_hp(free_path);
  if (available_pages < 0) {
    return false;
  }
  if (available_pages >= (int)threads) {
    return true;
  }
  char nr_path[256];
  sprintf(nr_path,
          "/sys/devices/system/node/node%lu/hugepages/"
          "hugepages-2048kB/nr_hugepages",
          node);
  int set_pages = read_hp(nr_path);
  set_pages = set_pages < 0 ? 0 : set_pages + threads - available_pages;
  huge_pages = write_hp(nr_path, set_pages);

  // Check if the value was really written.
  if (huge_pages) {
    int nr_hugepages = read_hp(nr_path);
    // Failed to write values properly?
    if (nr_hugepages < set_pages) {
      return false;
    }
  } else {
    return false;
  }

  return true;
}

static bool AddNodeHugePages(size_t threads, size_t node) {
  char nr_path[256];
  sprintf(nr_path,
          "/sys/devices/system/node/node%lu/hugepages/"
          "hugepages-2048kB/nr_hugepages",
          node);
  int set_pages = read_hp(nr_path);
  set_pages = set_pages + threads;
  huge_pages = write_hp(nr_path, set_pages);

  // Check if the value was really written.
  if (huge_pages) {
    int nr_hugepages = read_hp(nr_path);
    // Failed to write values properly?
    if (nr_hugepages < set_pages) {
      return false;
    }
  }

  return true;
}

// One thread should allocate 2 MiB of Large Pages.
bool InitHugePages(size_t threads, size_t max_large_pages) {
  // Detect number of nodes in the system.
  const size_t nodes = numa_max_node();
  const size_t hw_threads = numa_num_possible_cpus();
  if (opt_debug || nodes > 0) {
    applog(LOG_BLUE, "Detected %lu NUMA node(s).", nodes + 1);
  }

  int node_cpus[64];
  memset(node_cpus, 0, 64 * sizeof(int));

  for (size_t node = 0; node <= nodes; ++node) {
    struct bitmask *mask = numa_allocate_cpumask();
    numa_node_to_cpus(node, mask);
    for (size_t i = 0; i < hw_threads; ++i) {
      node_cpus[node] += numa_bitmask_isbitset(mask, i);
    }
    numa_free_nodemask(mask);
  }

  // Spread Large Pages allocation through each node.
  if (threads > hw_threads) {
    applog(LOG_BLUE, "Using %d threads on %d hw_threads.", threads, hw_threads);
    for (size_t node = 0; node <= nodes; ++node) {
      int t = node_cpus[node];
      node_cpus[node] = ceil((double)node_cpus[node] *
                             ((double)threads / (double)hw_threads));
      applog(LOG_BLUE, "Treating node %d with %d threads as %d threads.", node,
             t, node_cpus[node]);
    }
  }

  size_t *to_reinitialize = (size_t *)malloc((nodes + 1) * sizeof(size_t));
  size_t nodes_ok = 0;
  size_t nodes_err = 0;
  for (size_t node = 0; node <= nodes; ++node) {
    if (!InitNodeHugePages(node_cpus[node] * max_large_pages, node)) {
      to_reinitialize[nodes_err++] = node;
      applog(LOG_ERR, "Failed to initialize Large Pages on node%lu", node);
    } else {
      if (opt_debug || node > 0) {
        applog(LOG_BLUE, "Successfully initialized Large Pages on node%lu",
               node);
      }
      nodes_ok++;
      huge_pages = true;
    }
  }

  const size_t bad_nodes = nodes_err;
  if (bad_nodes > 0) {
    size_t id = 0;
    size_t id2 = 0;
    // Try to allocate failed nodes allocation on other nodes.
    do {
      id2 = id;
      for (size_t node = 0; node <= nodes; ++node) {
        bool invalid_node = false;
        for (size_t i = 0; i < bad_nodes; ++i) {
          if (to_reinitialize[i] == node) {
            invalid_node = true;
          }
        }
        if (!invalid_node) {
          if (AddNodeHugePages(node_cpus[node] * max_large_pages, node)) {
            applog(LOG_WARNING,
                   "Initialized node%lu Large Pages allocation on node%lu",
                   to_reinitialize[id++], node);
            nodes_err--;
            nodes_ok++;
          }
        }
      }
    } while (id != id2);
  }
  if (nodes_ok > 0) {
    huge_pages = true;
  }
  free(to_reinitialize);
  return huge_pages;
}

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
void *AllocateLargePagesMemory(size_t size) {
  // Needs to be multiple of Large Pages (2 MiB).
#if defined(__FreeBSD__)
  void *mem =
      mmap(0, size, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALIGNED_SUPER | MAP_PREFAULT_READ,
           -1, 0);
#else
  void *mem = mmap(0, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE |
                       MAP_HUGE_2MB,
                   0, 0);
#endif

  if (mem == MAP_FAILED) {
    if (huge_pages) {
      applog(LOG_ERR, "Huge Pages allocation failed.");
    }

    // Retry without huge pages.
#if defined(__FreeBSD__)
    mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
               0);
#else
    mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
               0);
#endif
  }

  return mem == MAP_FAILED ? NULL : mem;
}

void DeallocateLargePagesMemory(void **memory) {
  // Needs to be multiple of Large Pages (2 MiB).
  int status = munmap(*memory, GetProperSize(currently_allocated));
  if (status != 0) {
    applog(LOG_ERR, "Could not properly deallocate memory!");
  }
  *memory = NULL;
  allocated_hp = false;
}

#endif // __MINGW32__

void *AllocateMemory(size_t size) {
  void *mem = AllocateLargePagesMemory(size);
  if (mem == NULL) {
    if (huge_pages) {
      applog(LOG_WARNING, "Using malloc as allocation method.");
      static int ct = 0;
      if (ct == 0) {
        ++ct;
        applog(LOG_ERR, "Consider Restarting the PC");
      }
    }
#ifdef __MINGW32__
    mem = _aligned_malloc(size, 64);
#else
    mem = aligned_alloc(64, size);
#endif
    allocated_hp = false;
    if (mem == NULL) {
      applog(LOG_ERR, "Could not allocate any memory for thread.");
      exit(1);
    }
  } else {
    allocated_hp = true;
  }
  currently_allocated = size;
  return mem;
}

void DeallocateMemory(void **memory) {
  if (allocated_hp) {
    DeallocateLargePagesMemory(memory);
    // Wait a while (25ms) after deallocation. Should help with
    // fast allocation afterwards.
    usleep(25000);
  } else if (*memory != NULL) {
    // No special method of allocation was used.
    free(*memory);
  }
}

void PrepareMemory(void **memory, size_t size) {
  if (GetProperSize(currently_allocated) < GetProperSize(size)) {
    if (*memory != NULL) {
      DeallocateMemory(memory);
    }
    *memory = (void *)AllocateMemory(GetProperSize(size));
  }
}
