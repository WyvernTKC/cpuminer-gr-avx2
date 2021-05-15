#include "virtual_memory.h"
#include "miner.h" // applog
#include "stdio.h"

static bool huge_pages = false;
__thread bool allocated_hp = false;
__thread size_t currently_allocated = 0;

#ifdef __MINGW32__
// Windows
#define UNICODE
#define _UNICODE
#include <ntsecapi.h>
#include <ntstatus.h>
#include <tchar.h>
#include <windows.h>
#include <winsock2.h>
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
    if (opt_debug) {
      applog(LOG_DEBUG, "Huge Pages: Failed token query.");
    }
    return FALSE;
  }

  NTSTATUS status;
  BOOL result = FALSE;
  LSA_HANDLE handle;
  if ((status = OpenPolicy(NULL, POLICY_ALL_ACCESS, &handle))) {
    applog(LOG_ERR, "Huge Pages: failed to open policy %u",
           LsaNtStatusToWinError(status));
  }

  if ((status =
           SetPrivilege(handle, user->User.Sid, _T(SE_LOCK_MEMORY_NAME)))) {
    applog(LOG_NOTICE, "Huge pages: Failed to add account rights %lu",
           LsaNtStatusToWinError(status));
    result = FALSE;
  } else {
    applog(LOG_NOTICE,
           "Huge pages support was successfully enabled, but reboot "
           "is required to use it");
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

bool InitHugePages(size_t threads) {
  huge_pages = TrySetLockPagesPrivilege();
  return huge_pages
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
  VirtualFree(*memory, currently_allocated, MEM_RELEASE);
  *memory = NULL;
  allocated_hp = false;
}

#else
// Linux
#include <sys/mman.h>
static inline int read_hp(const char *path) {
  FILE *fd;
  fd = fopen(path, "r");
  if (fd == NULL) {
    return -1;
  }

  uint64_t value = 0;
  size_t read = fscanf(fd, "%lu", &value);
  fclose(fd);
  if (ferror(fd) != 0 || read != 1) {
    return -2;
  }
  return (int)value;
}

static inline bool write_hp(const char *path, uint64_t value) {
  FILE *fd;
  fd = fopen(path, "w");
  if (fd == NULL) {
    return false;
  }

  fprintf(fd, "%lu", value);
  fclose(fd);
  if (ferror(fd) != 0) {
    return false;
  }
  return true;
}

// One thread should allocate 2 MiB of Large Pages.
bool InitHugePages(size_t threads) {
  const char *free_path = "/sys/devices/system/node/node0/hugepages/"
                          "hugepages-2048kB/free_hugepages";
  int available_pages = read_hp(free_path);
  if (available_pages < 0) {
    huge_pages = false;
    return huge_pages;
  }
  if (available_pages >= (int)threads) {
    huge_pages = true;
    return huge_pages;
  }
  const char *nr_path = "/sys/devices/system/node/node0/hugepages/"
                        "hugepages-2048kB/nr_hugepages";
  int set_pages = read_hp(nr_path);
  set_pages = set_pages < 0 ? 0 : set_pages;
  huge_pages = write_hp(nr_path, (size_t)set_pages + threads - available_pages);
  return huge_pages;
}

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
void *AllocateLargePagesMemory(size_t size) {
  // Needs to be multiple of Large Pages (2 MiB).
  size = ((size / 2097152) * 2097152) + 2097152;
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
      applog(LOG_ERR,
             "Huge Pages allocation failed. Run with root privileges.");
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
  size_t size = ((currently_allocated / 2097152) * 2097152) + 2097152;
  int status = munmap(*memory, size);
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
    if (opt_debug) {
      applog(LOG_NOTICE, "Using malloc as allocation method");
    }
    mem = malloc(size);
    allocated_hp = false;
    if (mem == NULL) {
      applog(LOG_ERR, "Could not allocate any memory for thread");
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
  } else if (*memory != NULL) {
    // No special method of allocation was used.
    free(*memory);
  }
}

void PrepareMemory(void **memory, size_t size) {
  if (*memory != NULL) {
    DeallocateMemory(memory);
  }
  *memory = (void *)AllocateMemory(size);
}
