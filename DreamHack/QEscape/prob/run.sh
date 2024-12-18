#!/bin/bash
./qemu-system-x86_64 \
    -L ./bios \
    -kernel bzImage \
    -initrd $1 \
    -cpu kvm64,+smep,+smap \
    -m 128M \
    -append "console=ttyS0 oops=panic panic=1 quiet" \
    -nographic \
    -no-reboot \
    -net user -net nic -device e1000 \
    -device EscapeDev \
    -enable-kvm