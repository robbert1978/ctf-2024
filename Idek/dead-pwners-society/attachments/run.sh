exec qemu-system-x86_64 \
    -kernel ./bzImage \
    -cpu qemu64,+smep,+smap \
    -m 2G \
    -smp 2 \
    -drive file=root.img,if=ide \
    -append "console=ttyS0 root=/dev/sda ignore_loglevel nokaslr kpti=1" \
    -nographic \
    -no-reboot \
    -s
