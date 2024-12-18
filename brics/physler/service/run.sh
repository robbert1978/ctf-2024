#!/bin/sh

qemu-system-x86_64 \
    -m 96M \
    -cpu kvm64,+smep,+smap \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 nokaslr kpti=1 quiet panic=1" \
    -enable-kvm -s
