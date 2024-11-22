#!/bin/bash

set -exo  pipefail

export ARCH=arm64
export CROSS_COMPILE=$(dirname $(realpath $0))/toolchain/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-

pushd linux/

make clean
make defconfig
make -j28

popd
