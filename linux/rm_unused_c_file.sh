#!/bin/bash

set -exo pipefail


SRC_PATH=$(dirname $0)
C_FILES=$( find $SRC_PATH -name "*.c" \
	-not -path "$SRC_PATH/scripts/*" \
	-not -path "$SRC_PATH/kernel/bounds.c" \
	-not -path "$SRC_PATH/arch/arm64/kernel/asm-offsets.c" \
	-not -path "$SRC_PATH/lib/vdso/gettimeofday.c" \
	-not -path "$SRC_PATH/usr/gen_init_cpio.c" \
	-not -path "$SRC_PATH/mm/percpu-vm.c" \
	-not -path "$SRC_PATH/lib/gen_crc32table.c" \
	-not -path "$SRC_PATH/drivers/tty/vt/conmakehash.c" )

#echo $C_FILES

for FILE in $C_FILES; do
	if [ ! -f ${FILE%.c}.o ]; then
		rm $FILE
	fi
done
