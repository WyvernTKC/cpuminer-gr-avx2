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
mkdir -p bin/unix/{Medium,Heavy} 2>/dev/null

DFLAGS="-Wall -fno-common -Wno-comment -Wno-maybe-uninitialized"

# 1 - Architecture
# 2 - Output suffix
# 3 - Additional options
compile() {

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=${1} ${3} ${DFLAGS}" ./configure --with-curl
make -j 16
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


#AVX2+ Light
# Haswell AVX2 AES
# GCC 9 doesn't include AES with core-avx2
compile "core-avx2" "avx2" "-maes"

# AMD Zen1 AVX2 SHA
compile "znver1" "zen"

# AMD Zen2 AVX2 SHA
compile "znver2" "zen2"

# AMD Zen3 AVX2 SHA VAES
compile "znver2" "zen3" "-mvaes"

# Icelake AVX512 SHA VAES
compile "icelake-client" "avx512-sha-vaes"

# Rocketlake AVX512 SHA AES
compile "cascadelake" "avx512-sha" "-msha"

# Slylake-X AVX512 AES
compile "skylake-avx512" "avx512"


#AVX2+ Medium
# Haswell AVX2 AES
# GCC 9 doesn't include AES with core-avx2
compile "core-avx2" "avx2" "-maes -DGR_4WAY_MEDIUM" "Medium"

# AMD Zen1 AVX2 SHA
compile "znver1" "zen" " -DGR_4WAY_MEDIUM" "Medium"

# AMD Zen2 AVX2 SHA
compile "znver2" "zen2" "-DGR_4WAY_MEDIUM" "Medium"

# AMD Zen3 AVX2 SHA VAES
compile "znver2" "zen3" "-mvaes -DGR_4WAY_MEDIUM" "Medium"

# Icelake AVX512 SHA VAES
compile "icelake-client" "avx512-sha-vaes" "-DGR_4WAY_MEDIUM" "Medium"

# Rocketlake AVX512 SHA AES
compile "cascadelake" "avx512-sha" "-msha -DGR_4WAY_MEDIUM" "Medium"

# Slylake-X AVX512 AES
compile "skylake-avx512" "avx512" "-DGR_4WAY_MEDIUM" "Medium"


#AVX2+ Heavy
# Haswell AVX2 AES
# GCC 9 doesn't include AES with core-avx2
compile "core-avx2" "avx2" "-maes -DGR_4WAY_HEAVY" "Heavy"

# AMD Zen1 AVX2 SHA
compile "znver1" "zen" "-DGR_4WAY_HEAVY" "Heavy"

# AMD Zen2 AVX2 SHA
compile "znver2" "zen2" "-DGR_4WAY_HEAVY" "Heavy"

# AMD Zen3 AVX2 SHA VAES
compile "znver2" "zen3" "-mvaes -DGR_4WAY_HEAVY" "Heavy"

# Icelake AVX512 SHA VAES
compile "icelake-client" "avx512-sha-vaes" "-DGR_4WAY_HEAVY" "Heavy"

# Rocketlake AVX512 SHA AES
compile "cascadelake" "avx512-sha" "-msha -DGR_4WAY_HEAVY" "Heavy"

# Slylake-X AVX512 AES
compile "skylake-avx512" "avx512" "-DGR_4WAY_HEAVY" "Heavy"
