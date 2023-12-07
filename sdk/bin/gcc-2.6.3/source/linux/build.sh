#!/bin/bash
# This has been tested in WSL, however a question about the line endings of patches remains.
# If the line endings of this script (And the .patch files in the patch folder) are CR LF instead of LF, this will fail.
# setup-linux.sh will fix these files as part of its execution.

# Clear old folder / builds.
echo "Removing old build."
rm -rf build/
rm -rf gcc-2.6.3/

# Install software necessary to build GCC.
echo "Installing prerequisite software..."
sudo apt-get update
sudo apt-get install -y build-essential gcc gcc-multilib tar

# Extract GCC 2.6.3 source code.
echo "Extracting GCC 2.6.3 source code..."
tar xvf ../gcc-2.6.3.tar.bz2
cd gcc-2.6.3/

# Apply changes to GCC source code.
echo "Applying changes to GCC source code..."
chmod -R +w *
sed -i -- 's/include <varargs.h>/include <stdarg.h>/g' *.c

patch -u -p1 obstack.h -i ../patches/obstack-2.7.2.h.patch
patch -u -p1 sdbout.c -i ../patches/sdbout-2.6.3.c.patch
patch -u -p1 cp/g++.c -i ../patches/g++-2.6.3.c.patch
patch -u -p1 gcc.c -i ../patches/gcc-2.6.3.c.patch
patch -su -p1 < ../patches/psx.patch

touch -c cp/parse.y cp/parse.h cp/parse.c
touch insn-config.h

# Configure build
echo "Configuring build..."
./configure \
    --target=mips-sony-psx \
    --prefix=/opt/cross \
    --with-endian-little \
    --with-gnu-as \
    --host=i386-pc-linux \
    --build=i386-pc-linux

# Build GCC
echo "Building GCC..."
make cpp cc1 xgcc cc1plus g++ CFLAGS="-std=gnu89 -m32 -static -Dbsd4_4 -Dmips -march=i686 -DHAVE_STRERROR"

# Setup output folder containing all the binaries.
echo "Success"
mv xgcc gcc
mkdir ../build/ && cp cpp cc1 gcc cc1plus g++ ../build/ || true

# Cleanup
cd ../
rm -rf gcc-2.6.3/
