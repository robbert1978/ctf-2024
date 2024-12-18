#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("./prob_patched")
libc = ELF("./libc.so.6")
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


def add_finder(size, keyword, type=1) -> int:
    p.sendlineafter(b'select one plz : ', b'1')
    p.sendlineafter(b'size of finder keyword : ', str(size).encode())
    p.sendlineafter(b'Give your keyword:', keyword)
    p.sendlineafter(
        b'Type of your keyword /1(Country) or 2(Capital)/: ',  str(type).encode())

    p.recvuntil(b'[Your random identification number is ')
    num = int(p.recvuntil(b'.').replace(b'.', b'').decode())
    return num


def del_finder(num, wait=True):
    if wait:
        p.recvuntil(b'select one plz : ')
    p.sendline(b'3')
    p.sendlineafter(
        b'give your random identification number : ', str(num).encode())


_ = add_finder(20, b'vietnam')
p.recvuntil(b'==========SEND SYSTEM==========\n')
# del_finder(_, False)

p.interactive()
