#!/bin/bash

set -exo  pipefail

export ARCH=arm64
export CROSS_COMPILE=$(dirname $(realpath $0))/toolchain/bin/aarch64-linux-musl-

pushd linux/

make clean
make defconfig
make -j28
make headers_install

popd
