#!/bin/bash

qemu-system-aarch64 -M virt,gic-version=3,iommu=smmuv3 \
	-nographic -m 1024 -smp 16 \
	-cpu cortex-a53 \
	-kernel arch/arm64/boot/Image \
	-initrd qemu/initramfs.cpio.gz \
	--append "root=/dev/ram nokaslr" \
	-s -S
