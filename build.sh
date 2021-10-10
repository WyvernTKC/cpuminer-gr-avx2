#!/bin/bash

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done


GCC_VERSION=$(gcc -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$/&00/')


CFLAGS="-O3 -march=native -mtune=native"

#
# Auto detect which gcc version we have
#
if [[ "$GCC_VERSION" == "9" ]]
then
   # For GCC-9 && GCC-8
   echo "Found GCC verison 9"
   export CXXFLAGS="$CFLAGS -std=c++2a -fconcepts -Wno-ignored-attributes"
elif [[ "$GCC_VERSION" == "10" ]]
then
   echo "Found GCC verison 10"
   export CXXFLAGS="$CFLAGS -std=c++20 -Wno-ignored-attributes"
else
   echo "UNKNOWN gcc version defaulting to version 10"
   export CXXFLAGS="$CFLAGS -std=c++20 -Wno-ignored-attributes"
fi

#
# configure with CXXFLAGS and CFLAGS 
#
./configure CXXFLAGS="$CXXFLAGS" CFLAGS="$CFLAGS" --with-curl


#
# Make with a thread for each core we have
#
make -j $(nproc)

strip -s cpuminer
