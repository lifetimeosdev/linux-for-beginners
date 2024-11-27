### Linux for beginners

- Make Linux code easy to learn for beginners.

- Make Linux source code easy to read and debug to follow the code path.

### Quick start (Dev on Ubuntu 24.04)

1. Install `VSCode`, `C/C++ extension` and `gdb-multiarch` on a Linux distro.
1. Using `./build_toolchain.sh` to build musl-gcc toolchain.
1. Using `./build_linux.sh` to build the linux source code.
1. Using `./make_initramfs.sh` to make initramfs including busybox.
1. Using `./run.sh` to start the qemu and press F5 to start the debugger.

## References
1. Linux: https://www.kernel.org/
1. musl libc: https://musl.libc.org/
1. busybox: https://www.busybox.net/
1. musl-cross-make: https://github.com/richfelker/musl-cross-make

### Disclaimer

- Focus on arm64(aarch64) only. Maybe not right for other architecture(amd64, ia64...) or 32bit architecture(i386, arm...).

- Learning purpose only and DO NOT use my modified code in production before tests.

- Some of my modification may be not the orginal intent of upstream source code. Please refer to upstream source code if you want to contribute to upstream repo.
