#!/bin/bash

qemu-system-x86_64 \
    -cpu qemu64,+smap \
    -m 4096M \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -append "nokaslr console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on" \
    -nographic \
    -netdev user,id=net0,hostfwd=tcp::22222-:22222 \
    -device e1000,netdev=net0 \
    -no-reboot -s