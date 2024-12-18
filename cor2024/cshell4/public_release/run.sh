#!/bin/bash
# cp * /tmp
# cd /tmp

# chmod 777 flag.txt

python3 chall-setup.py > /dev/null
# chmod +x /tmp/boat
LD_PRELOAD="./libcrypto.so.3 ./libc.so.6" ./boat 1032 &
LD_PRELOAD="./libcrypto.so.3 ./libc.so.6" ./boat 1033 &
LD_PRELOAD="./libcrypto.so.3 ./libc.so.6" ./boat 1035 &
LD_PRELOAD="./libcrypto.so.3 ./libc.so.6" ./boat 1024 &
LD_PRELOAD="./libcrypto.so.3 ./libc.so.6" ./boat 1031
