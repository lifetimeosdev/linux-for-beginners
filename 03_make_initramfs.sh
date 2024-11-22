#!/bin/bash

set -exo pipefail

export ARCH=arm64
export CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-

pushd ./busybox
make clean

OUTPUT_PATH=./busybox_rootfs
make defconfig
cp ../misc/busybox_config .config

rm -rf $OUTPUT_PATH
make -j28 CONFIG_PREFIX=$OUTPUT_PATH install
cp ./busybox_unstripped $OUTPUT_PATH/bin/busybox*

pushd $OUTPUT_PATH

cat >./init <<EOF
#!/bin/sh

set -ex pipefail

mkdir /proc && mount -t proc none /proc
mkdir /sys && mount -t sysfs none /sys

/sbin/mdev -s

exec /sbin/init

EOF

chmod +x ./init

find . -print0 | cpio --null -ov --format=newc > ../../misc/initramfs.cpio

popd
popd

gzip -f ./misc/initramfs.cpio
