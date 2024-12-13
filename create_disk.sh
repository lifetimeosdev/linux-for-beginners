#!/bin/bash

set -exo  pipefail

# qcow2
# qemu-img create -f qcow2 ./misc/disk.qcow2 32M
#  run with:	-drive file=./misc/disk.qcow2,id=d0,if=none,format=qcow2,media=disk \

# raw (easy to debug)
dd if=/dev/zero of=./misc/disk.raw bs=1M count=32
# run with:	-drive file=./misc/disk.raw,id=d0,if=none,format=raw,media=disk
