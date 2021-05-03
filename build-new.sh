#!/bin/bash

#if [ "$OS" = "Windows_NT" ]; then
#    ./mingw64.sh
#    exit 0
#fi

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

# Ubuntu 10.04 (gcc 4.4)
# extracflags="-O3 -march=native -Wall -D_REENTRANT -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

# Debian 7.7 / Ubuntu 14.04 (gcc 4.7+)
#extracflags="$extracflags -Ofast -flto -fuse-linker-plugin -ftree-loop-if-convert-stores"

#CFLAGS="-O3 -march=native -Wall" ./configure --with-curl --with-crypto=$HOME/usr
#CFLAGS="-O3 -march=broadwell -flto -fuse-linker-plugin -ftree-loop-if-convert-stores -Wall" LDFLAGS="-static" ./configure --with-curl --enable-static LIBS="-lpthread -ldl" 
#CFLAGS="-O3 -fno-tree-vectorize -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -mavx -mavx2 -maes -Wall" LDFLAGS="-static" ./configure --with-curl --enable-static LIBS="-lpthread -ldl" 
#CFLAGS="-O3 -march=native -Wall" CXXFLAGS="$CFLAGS -std=gnu++11" ./configure --with-curl
#CFLAGS="-O0 -fprofile-generate=./gcda -mbmi2 -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -mavx -mavx2 -maes -mpclmul -Wall" LDFLAGS="-static -lgcov --coverage" ./configure --with-curl --enable-static LIBS="-lpthread -ldl"
#AVX
#CFLAGS="-O3 -march=broadwell -fno-strict-aliasing -fomit-frame-pointer -flto -fuse-linker-plugin -ftree-ter -fprofile-correction -Wno-error=coverage-mismatch -fprofile-use=./gcda -mbmi2 -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -mavx -mavx2 -maes -mpclmul -mvzeroupper -Wall" LDFLAGS="-static" ./configure --with-curl --enable-static LIBS="-lpthread -ldl"
CFLAGS="-O3 -march=broadwell -fno-strict-aliasing -fomit-frame-pointer -fuse-linker-plugin -ftree-ter -mbmi2 -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -mavx -mavx2 -maes -mpclmul -mvzeroupper -Wall" LDFLAGS="-static" ./configure --with-curl --enable-static LIBS="-lpthread -ldl"
#SSE4.2
#CFLAGS="-O0 -fprofile-generate=./gcdasse -msse2 -msse3 -msse4.1 -msse4.2 -maes -Wall" LDFLAGS="-static -lgcov --coverage" ./configure --with-curl --enable-static LIBS="-lpthread -ldl"
#CFLAGS="-O3 -fno-strict-aliasing -fomit-frame-pointer -flto -fuse-linker-plugin -ftree-ter -fprofile-correction -Wno-error=coverage-mismatch -fprofile-generate=./gcdasse -msse2 -maes -Wall" LDFLAGS="-static" ./configure --with-curl --enable-static LIBS="-lpthread -ldl"
#CFLAGS="-O3 -march=knl -mprefer-vector-width=512 -fno-strict-aliasing -fomit-frame-pointer -flto -fuse-linker-plugin -ftree-ter -fprofile-correction -Wno-error=coverage-mismatch -fprofile-use=./gcda -mbmi2 -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -mavx -mavx2 -maes -mpclmul -mvzeroupper -Wall" LDFLAGS="-static" ./configure --with-curl --enable-static LIBS="-lpthread -ldl"
#CFLAGS="-O3 -fprofile-use=/tmp/gcda -Wno-error=coverage-mismatch -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -maes -Wall " LDFLAGS="-static -lgcov --coverage" ./configure --with-curl --enable-static LIBS="-lpthread -ldl"
make -j 8

strip -s cpuminer
mv cpuminer cpuminer-gr-avx2
