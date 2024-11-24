#!/bin/bash

set -exo  pipefail

pushd ./musl-cross-make

make -j28
make install
rm -rf ../toolchain/*
cp -r ./output/* ../toolchain/

popd
