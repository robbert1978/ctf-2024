#!/bin/sh

exec /usr/bin/qemu-system-arm \
    -M virt,highmem=off \
    -m 256M \
    -kernel zImage \
    -initrd rootfs.cpio \
    -append "root=/dev/ram rdinit=/init" \
    -serial /dev/null \
    -nographic \
    -monitor /dev/null