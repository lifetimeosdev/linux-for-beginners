#!/bin/bash

set -exo pipefail

pushd ./busybox-1.28.4
export ARCH=arm64
export CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-
make clean

OUTPUT_PATH=./busybox_rootfs
make defconfig
cp ../busybox_config .config

make -j28 CONFIG_PREFIX=$OUTPUT_PATH install

pushd $OUTPUT_PATH
touch ./init
chmod +x ./init
cat >./init <<EOF
#!/bin/sh

set -ex pipefail

mkdir /proc && mount -t proc none /proc
mkdir /sys && mount -t sysfs none /sys

/sbin/mdev -s

exec /sbin/init

EOF

find . -print0 | cpio --null -ov --format=newc > ../../qemu/initramfs.cpio

popd
popd

gzip -f ./qemu/initramfs.cpio
