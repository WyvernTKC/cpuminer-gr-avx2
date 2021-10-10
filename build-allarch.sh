#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

rm -r bin/unix 2>/dev/null
rm cpuminer 2>/dev/null
mkdir -p bin/unix/ 2>/dev/null

DCFLAGS="-Wall -fno-common -Wextra -Wabi"
DCXXFLAGS="-Wno-ignored-attributes"

# 1 - Architecture
# 2 - Output suffix
# 3 - Additional options
compile() {

  echo "Compile: $@" 1>&2
  make distclean || echo clean
  rm -f config.status
  ./autogen.sh || echo done
  CFLAGS="-O3 -march=${1} ${3} ${DCFLAGS}" \
  CXXFLAGS="$CFLAGS -std=c++20 ${DCXXFLAGS}" \
  ./configure --with-curl
  make -j $(nproc)
  strip -s cpuminer
  mv cpuminer bin/unix/${4}/cpuminer-${2}

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
