#!/bin/bash
#
# Script for building Windows binaries release package using mingw.
# Requires a custom mingw environment, not intended for users.
#
# Compiles Windows EXE files for selected CPU architectures, copies them
# as well as some DLLs that aren't available in most Windows environments
# into a release folder ready to be zipped and uploaded.

# define some local variables

export LOCAL_LIB="$HOME/usr/lib"
export CONFIGURE_ARGS="--with-curl=$LOCAL_LIB/curl --with-crypto=$LOCAL_LIB/openssl --host=x86_64-w64-mingw32"
export MINGW_LIB="/usr/x86_64-w64-mingw32/lib"
# set correct gcc version
export GCC_MINGW_LIB="/usr/lib/gcc/x86_64-w64-mingw32/10-win32"
# used by GCC
export LDFLAGS="-L$LOCAL_LIB/curl/lib/.libs -L$LOCAL_LIB/gmp/.libs -L$LOCAL_LIB/openssl"

# make link to local gmp header file.
rm ./gmp.h 2>/dev/null
ln -s $LOCAL_LIB/gmp/gmp.h ./gmp.h

# edit configure to fix pthread lib name for Windows.
#sed -i 's/"-lpthread"/"-lpthreadGC2"/g' configure.ac

# make release directory and copy selected DLLs.

rm -rf bin/win/ 2>/dev/null
mkdir -p bin/win/ 2>/dev/null


cp $MINGW_LIB/zlib1.dll bin/win/
cp $MINGW_LIB/libwinpthread-1.dll bin/win/
cp $GCC_MINGW_LIB/libstdc++-6.dll bin/win/
cp $GCC_MINGW_LIB/libgcc_s_seh-1.dll bin/win/
cp $LOCAL_LIB/openssl/libcrypto-1_1-x64.dll bin/win/
cp $LOCAL_LIB/curl/lib/.libs/libcurl-4.dll bin/win/


# This flag should be removed for Older Windows versions. It is used to enable
# CPU Groups that are present in multi NUMA configs.
# "-D_WIN32_WINNT=0x0601"

DCFLAGS="-Wall -fno-common -Wextra -Wabi -D_WIN32_WINNT=0x0601"
DCXXFLAGS="-Wno-ignored-attributes"

# Start building...

# 1 - Architecture
# 2 - Output suffix
# 3 - Additional options
compile() {

  echo "Compile: $@" 1>&2
  make distclean || echo clean
  rm -f config.status
  ./autogen.sh || echo done

  # For GCC-9 && GCC-8
  #CXXFLAGS="$CFLAGS -std=c++2a -fconcepts -Wno-ignored-attributes" \

  CFLAGS="-O3 -march=${1} ${3} ${DFLAGS}" \
  CXXFLAGS="$CFLAGS -std=c++20 ${DCXXFLAGS}"  \
  ./configure ${CONFIGURE_ARGS}
  make -j $(nproc)
  strip -s cpuminer.exe
  mv cpuminer.exe bin/win/${4}/cpuminer-${2}.exe

}


#Non-AES
# Generic SSE2
compile "x86-64" "sse2" "-msse"

# Core2 SSSE3
compile "core2" "ssse3"

# Nehalem SSE4.2
compile "corei7" "sse42"


#AES
# Westmere SSE4.2 AES
compile "westmere" "aes-sse42" "-maes"

# Sandybridge AVX AES
compile "corei7-avx" "avx" "-maes"


#AVX2+
# Haswell AVX2 AES
# GCC 9 doesn't include AES with core-avx2
compile "core-avx2" "avx2" "-maes"

# AMD Zen1 AVX2 SHA
compile "znver1" "zen" "-mtune=znver1"

# AMD Zen2 AVX2 SHA
compile "znver2" "zen2" "-mtune=znver2"

# AMD Zen3 AVX2 SHA VAES
# GCC 10
compile "znver3" "zen3" "-mtune=znver3"
# GCC 9
# compile "znver2" "zen3" "-mvaes -mtune=znver2"

# Icelake AVX512 SHA VAES
compile "icelake-client" "avx512-sha-vaes" "-mtune=intel"

# Rocketlake AVX512 SHA AES
compile "cascadelake" "avx512-sha" "-msha -mtune=intel"

# Slylake-X AVX512 AES
compile "skylake-avx512" "avx512" "-mtune=intel"

# Remove gmp.h
rm ./gmp.h 2>/dev/null
