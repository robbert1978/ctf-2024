#!/bin/sh
if [ -d "/app" ]; then
    cd /app
fi
exec ./qemu-system-x86_64 \
    -L ./pc-bios \
    -m 64M \
    -nographic \
    -kernel bzImage.old \
    -initrd rootfs.cpio.gz \
    -append "console=ttyS0 loglevel=7 oops=panic panic=-1 kaslr" \
    -no-reboot \
    -cpu qemu64 \
    -monitor /dev/null \
    -sandbox on