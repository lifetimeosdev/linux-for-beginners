#!/bin/bash

set -exo  pipefail

export ARCH=arm64
export CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-

make clean
make defconfig
make -j28

./make_initramfs.sh
