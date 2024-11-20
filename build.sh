#!/bin/bash

set -exo  pipefail

export ARCH=arm64
export CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-

pushd linux/

make clean
make defconfig
make -j28

popd
