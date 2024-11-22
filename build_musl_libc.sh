#!/bin/bash

set -exo pipefail

export ARCH=aarch64
export CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-

pushd ./musl

rm -rf build

./configure --prefix=./build
make -j28
make install

popd
