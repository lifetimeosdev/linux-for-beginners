#!/bin/bash

qemu-system-aarch64 -M virt,gic-version=3,iommu=smmuv3 \
	-nographic -m 1024 -smp 1 \
	-cpu cortex-a53 \
	-kernel arch/arm64/boot/Image \
	-initrd qemu/initramfs.cpio.gz \
	--append "root=/dev/root nokaslr" \
	-device virtio-blk-device,drive=d0 \
	-drive file=./qemu/disk.qcow2,id=d0,if=none,format=raw,media=disk \
	-s -S
