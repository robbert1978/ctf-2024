#!/bin/sh

qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./initramfs.cpio.gz \
  -cpu qemu64,+smap,+smep \
  -nographic \
  -append "console=ttyS0 loadpin.enforce=0 kaslr" \
  -monitor /dev/null \
  -m 1G \
  -enable-kvm \
  -no-reboot -s