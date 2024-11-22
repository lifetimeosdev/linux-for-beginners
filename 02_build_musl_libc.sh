#!/bin/bash

set -exo pipefail

export ARCH=aarch64
export CROSS_COMPILE=$(dirname $(realpath $0))/toolchain/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-

pushd ./musl

rm -rf build

./configure --prefix=./build
make -j28
make install

popd
