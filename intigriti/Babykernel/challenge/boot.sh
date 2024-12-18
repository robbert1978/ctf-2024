#!/bin/bash

qemu-system-x86_64 \
    -m 64M \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kpti=off nokaslr" \
    -nographic \
    -no-reboot \
    -monitor /dev/null -s
