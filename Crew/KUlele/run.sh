#!/bin/bash
exec /usr/bin/qemu-system-x86_64 \
    -kernel ./bzImage \
    -m 256M \
    -initrd ./initramfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -cpu kvm64,+smep,+smap \
    -append "console=ttyS0 nokaslr kpti=1 panic=1 oops=panic trace_event=kmem" \
    -smp cores=2 \
    -s
