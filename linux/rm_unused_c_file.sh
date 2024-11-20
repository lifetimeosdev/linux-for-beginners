#!/bin/bash

set -exo pipefail

C_FILES=$( find . -name "*.c" \
	-not -path "./scripts/*" \
	-not -path "./kernel/bounds.c" \
	-not -path "./arch/arm64/kernel/asm-offsets.c" \
	-not -path "./lib/vdso/gettimeofday.c" \
	-not -path "./usr/gen_init_cpio.c" \
	-not -path "./mm/percpu-vm.c" \
	-not -path "./lib/gen_crc32table.c" \
	-not -path "./drivers/tty/vt/conmakehash.c" )

#echo $C_FILES

for FILE in $C_FILES; do
	if [ ! -f ${FILE%.c}.o ]; then
		rm $FILE
	fi
done
