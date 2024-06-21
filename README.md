# Endokernel: A Thread Safe Monitor for Lightweight Subprocess Isolation

This repo contains the source code of the endokernel used to make the paper public before publication, and you can compile it with the following command.

## Install

To build the endokernel, you can use the following command:

```bash
mkdir build
cd build && cmake ../src/libintravirt/ -DCFI=NEXPOLINE -DRSYSCALL=DISPATCH -DVDSO=ON -DMT=ON -DRANDOM=OFF -DAPPPERF=OFF -DSYSCALLFILTER=ON && make -j
```

The endokernel will be compiled in the `build` directory. 

However, to run the endokernel, you need to use the provided kernel and glibc patches. The kernel patch is in the `kernel_patch` directory, and the glibc patch is in the `glibc_patch` directory.

To make this process easier, we provide a pre-built image with our patches applied.

https://github.com/endokernel/runq/tree/main/kernel 

In order to use the pre-built image, you need to have a Ubuntu 20.10 and install the deb package, this will allow you to reboot and use our modified kernel.

You also need to install a patched glibc, because of the prefix used in building the glibc, we suggest you to build and install your own glibc. You can find the glibc patch in the `glibc_patch` directory.

However, you can also download the pre-built glibc from the following link:

https://github.com/endokernel/test/blob/master/prebuilt/glibc-nocet.zip

But just be aware that the prefix and you may need to add `LD_LIBRARY_PATH` to the `lib` directory of the glibc in order to use it.

## Run applications

The endokernel is easy to use, you can run the following command with any existing binary:

```bash
[path to libintravirt.so] [path to glibc]/lib [path to binary]
```

For example, if you want to run the `ls` command, you can use the following command:

```bash
./build/libintravirt.so ../glibc-nocet/install/lib ls
```

To get error messages, you can change `int quiet = 1;` to `int quiet = 0;` in `src/libintravirt/printf.c`.

## Compartmentalization

You can use the libiso inside the src directory to compartmentalize the applications as we described in the paper. 

## Other repos

### Runq

We modified [runq](https://github.com/endokernel/runq) to run the container with modified kernel, this allows you to test the endokernel with docker.
However, the environment has more restrictions, and not every benchmark can run in the container. 
And if the application does not involve any siganl, you can use normal kernel to run the application.

Because QEMU does not support the CET feature, you cannot test CET configurations with runq.

### Test

We provide a [test](https://github.com/endokernel/test) harness to test the endokernel with different benchmarks.
Because we need to a specific Ubuntu distribution to run the endokernel, the repo contains a Dockerfile to build the environment and you can run it with runq.
The test harness also contains prebuilt glibc and intravirt binaries in its Git LFS.
