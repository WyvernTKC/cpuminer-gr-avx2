if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS	= compat

ALL_INCLUDES	= @PTHREAD_FLAGS@ -fno-strict-aliasing $(JANSSON_INCLUDES) -I.

bin_PROGRAMS	= cpuminer

dist_man_MANS	= cpuminer.1

cpuminer_SOURCES = \
  cpu-miner.c \
  util.c \
  api.c \
  sysinfos.c \
  algo-gate-api.c \
  virtual_memory.c \
  msr_mod.cpp \
  crypto/c_keccak.c \
  algo/blake/sph_blake.c \
  algo/blake/blake512-hash-4way.c \
  algo/bmw/sph_bmw.c \
  algo/bmw/bmw512-hash-4way.c \
  algo/cubehash/cubehash_sse2.c\
  algo/cubehash/cube-hash-2way.c \
  algo/echo/sph_echo.c \
  algo/echo/echo-hash-4way.c \
  algo/echo/aes_ni/hash.c \
	algo/fugue/fugue-aesni.c \
	algo/fugue/sph_fugue.c \
  algo/gr/gr-gate.c \
  algo/gr/gr.cpp \
  algo/gr/gr-4way.cpp \
  algo/groestl/groestl512-hash-4way.c \
  algo/groestl/sph_groestl.c \
  algo/groestl/aes_ni/hash-groestl.c \
  algo/groestl/aes_ni/hash-groestl256.c \
  algo/hamsi/sph_hamsi.c \
  algo/hamsi/hamsi-hash-4way.c \
  algo/jh/sph_jh.c \
  algo/jh/jh-hash-4way.c \
  algo/keccak/sph_keccak.c \
  algo/keccak/keccak-hash-4way.c \
  algo/luffa/luffa_for_sse2.c \
  algo/luffa/luffa-hash-2way.c \
  algo/sha/sha256d.c \
  algo/sha/sha256-hash.c \
  algo/sha/sha256-hash-opt.c \
  algo/sha/sha2.c \
  algo/sha/sph_sha2.c \
  algo/sha/sha256-hash-2way-ni.c \
	algo/sha/sha256-hash-4way.c \
  algo/shabal/sph_shabal.c \
  algo/shabal/shabal-hash-4way.c \
  algo/shavite/sph_shavite.c \
  algo/shavite/sph-shavite-aesni.c \
  algo/shavite/shavite-hash-2way.c \
  algo/shavite/shavite-hash-4way.c \
  algo/simd/nist.c \
  algo/simd/simd-hash-2way.c \
	algo/simd/vector.c \
  algo/skein/sph_skein.c \
  algo/skein/skein-hash-4way.c \
  algo/whirlpool/sph_whirlpool.c \
  algo/whirlpool/whirlpool-hash-4way.c

disable_flags =

if USE_ASM
   cpuminer_SOURCES += asm/neoscrypt_asm.S
if ARCH_x86
   cpuminer_SOURCES += asm/sha2-x86.S asm/scrypt-x86.S asm/aesb-x86.S
endif
if ARCH_x86_64
   cpuminer_SOURCES += asm/sha2-x64.S asm/scrypt-x64.S asm/aesb-x64.S
endif
if ARCH_ARM
   cpuminer_SOURCES += asm/sha2-arm.S asm/scrypt-arm.S
endif
else
   disable_flags += -DNOASM
endif

if HAVE_WINDOWS
   cpuminer_SOURCES += compat/winansi.c
endif

cpuminer_LDFLAGS	= @LDFLAGS@
cpuminer_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ @NUMA_LIBS@ -lssl -lcrypto
#cpuminer_LDADD	= @LIBCURL@ @PTHREAD_LIBS@ @WS2_LIBS@ -lssl -lcrypto \
#									/usr/lib/x86_64-linux-gnu/libjansson.a

cpuminer_CPPFLAGS = @LIBCURL_CPPFLAGS@ $(ALL_INCLUDES)
cpuminer_CFLAGS   = -Wno-pointer-sign $(disable_flags)

if HAVE_WINDOWS
cpuminer_CFLAGS += -Wl,--stack,10485760 -Wno-pointer-to-int-cast
else
#cpuminer_LDADD += /usr/lib/x86_64-linux-gnu/libnuma.a
endif

if HAVE_WINDOWS
# use to profile an object
# gprof_cflags = -pg -g3
# cpuminer_LDFLAGS += -pg
# cpuminer_CFLAGS += -fno-inline-functions -static

# copy/paste from generated Makefile
common_ccflags = $(DEFS) $(ALL_INCLUDES) $(cpuminer_CPPFLAGS) $(CPPFLAGS) $(cpuminer_CFLAGS) $(CFLAGS)

# special CFLAGS (if you find a simpler way to do that tell me ;)
cpuminer-neoscrypt.o: neoscrypt.c
	@echo "CUSTOM ${@}: ${filter %.o,${^}} ${filter %.c,${^}}"
	$(CC) $(common_ccflags) -g -O3 $(gprof_cflags) -MT $@ -MD -MP -c -o $@ $<


endif
