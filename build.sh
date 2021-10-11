#!/bin/bash

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

GCC_VERSION=$(gcc --version | grep ^gcc | sed 's/^.* //g')
GCC_MAJOR=$(echo $GCC_VERSION | cut -d. -f1)

echo "Detected GCC ${GCC_VERSION} with Major ${GCC_MAJOR}"

if [[ $GCC_MAJOR == 8 || $GCC_MAJOR == 9 ]]; then

  CFLAGS="-O3 -march=native -mtune=native" \
  CXXFLAGS="$CFLAGS -std=c++2a -fconcepts -Wno-ignored-attributes" \
  ./configure --with-curl

elif [[ $GCC_MAJOR -ge 10 ]]; then

  CFLAGS="-O3 -march=native -mtune=native" \
  CXXFLAGS="$CFLAGS -std=c++20 -Wno-ignored-attributes" \
  ./configure --with-curl

else
  echo "GCC version >= 8 is required for compilation"
  exit
fi


make -j $(nproc)

strip -s cpuminer
