#!/bin/bash

qemu-system-aarch64 -M virt,gic-version=3,iommu=smmuv3 \
	-nographic -m 1024 -smp 1 \
	-cpu cortex-a53 \
	-kernel ./linux/arch/arm64/boot/Image \
	-initrd ./misc/initramfs.cpio.gz \
	--append "root=/dev/root nokaslr" \
	-device virtio-blk-device,drive=d0 \
	-drive file=./misc/disk.raw,id=d0,if=none,format=raw,media=disk
	-s -S
