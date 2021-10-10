#!/bin/bash

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

# For GCC-9 && GCC-8
#CXXFLAGS="$CFLAGS -std=c++2a -fconcepts -Wno-ignored-attributes" \

CFLAGS="-O3 -march=native -mtune=native" \
CXXFLAGS="$CFLAGS -std=c++20 -Wno-ignored-attributes" \
./configure --with-curl

make -j $(nproc)

strip -s cpuminer
