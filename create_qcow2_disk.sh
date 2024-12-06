#!/bin/bash

set -exo  pipefail

qemu-img create -f qcow2 ./misc/disk.qcow2 32M
