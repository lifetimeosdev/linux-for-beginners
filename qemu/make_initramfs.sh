#!/bin/bash

cd busybox-1.26.2
make defconfig
make menuconfig
make -j16
make CONFIG_PREFIX=./busybox_rootfs install
mkdir -p ./initramfs/{bin,dev,etc,home,mnt,proc,sys,usr}
pushd initramfs/dev/
sudo mknod -m 622 console c 5 1
sudo mknod -m 666 null c 1 3
sudo mknod -m 666 zero c 1 5
sudo mknod -m 666 ptmx c 5 2
sudo mknod -m 666 tty c 5 0
sudo mknod -m 444 random c 1 8
sudo mknod -m 444 urandom c 1 9
# sudo chown -v root:tty console ptmx tty
popd

pushd initramfs/
touch ./init
chmoe +x ./init
cat >./init <<EOF
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
exec /bin/sh
EOF
find . -print0 | cpio --null -ov --format=newc > ../initramfs.cpio
popd

gzip ./initramfs.cpio

