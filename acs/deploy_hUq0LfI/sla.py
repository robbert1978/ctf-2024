import random
from pwn import *

# context.log_level = "INFO"

PATCHED = 0
ONLINE = 1
OFFLINE = 2


def add(p, idx, name, topics, is_photo=False, width=0, height=0, photo=b""):
    p.sendlineafter(b": ", b"1")
    p.sendlineafter(b"? ", str(idx).encode())
    p.sendlineafter(b"? ", name)

    p.sendlineafter(b"? ", str(len(topics)).encode())
    for topic in topics:
        p.sendlineafter(b"topic> ", topic)

    if is_photo:
        p.sendlineafter(b"? ", b"y")
        p.sendlineafter(b"? ", str(width).encode())
        p.sendlineafter(b"? ", str(height).encode())
        sleep(0.5)
        p.sendafter(b">>\n", photo)
    else:
        p.sendlineafter(b"? ", b"n")


def vote(p, idx):
    p.sendlineafter(b": ", b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())


def delete(p, idx):
    p.sendlineafter(b": ", b"3")
    p.sendlineafter(b"? ", str(idx).encode())


# testcase1 : check general add + vote + delete (check vote rendering result is succefully uncovered) ---------------------------------------


def testcase1(ip):
    p = remote(ip, 13337)
    try:
        pictures = []

        our_picture = b"".join([random.choice([b"0", b"1"])
                               for i in range(0x2f*0x2f)])
        # print(our_picture)

        predicted_rendering_result = b""

        for i in range(0x2f):
            for j in range(0x2f):
                if our_picture[i*0x2f+j] == 0x30:
                    predicted_rendering_result += b"."
                else:
                    predicted_rendering_result += b"+"
            predicted_rendering_result += b"\n"

        pictures.append(predicted_rendering_result)

        # print(predicted_rendering_result)

        # add to 0
        add(p, 0, b"a"*30, [b"hello", b"world", b"asdf"],
            True, 0x2f, 0x2f, our_picture)
        k = p.recvuntil(b"input")
        if our_picture not in k or predicted_rendering_result not in k:
            p.close()
            return OFFLINE

        our_picture = b"".join([random.choice([b"0", b"1"])
                               for i in range(0x2f*0x2f)])
        # print(our_picture)

        predicted_rendering_result = b""

        for i in range(0x2f):
            for j in range(0x2f):
                if our_picture[i*0x2f+j] == 0x30:
                    predicted_rendering_result += b"."
                else:
                    predicted_rendering_result += b"+"
            predicted_rendering_result += b"\n"

        pictures.append(predicted_rendering_result)

        # add to 1
        add(p, 1, b"b"*30, [b"beat", b"hex", b"cart"],
            True, 0x2f, 0x2f, our_picture)
        k = p.recvuntil(b"input")
        if our_picture not in k or predicted_rendering_result not in k:
            p.close()
            return OFFLINE

        our_picture = b"".join([random.choice([b"0", b"1"])
                               for i in range(0x2f*0x2f)])
        # print(our_picture)

        predicted_rendering_result = b""

        for i in range(0x2f):
            for j in range(0x2f):
                if our_picture[i*0x2f+j] == 0x30:
                    predicted_rendering_result += b"."
                else:
                    predicted_rendering_result += b"+"
            predicted_rendering_result += b"\n"

        pictures.append(predicted_rendering_result)

        # add to 2
        add(p, 2, b"c"*30, [b"kill", b"the", b"flag"],
            True, 0x2f, 0x2f, our_picture)
        k = p.recvuntil(b"input")
        if our_picture not in k or predicted_rendering_result not in k:
            p.close()
            return OFFLINE

        # vote 0 check
        p.sendline(b"2")

        k = p.recvuntil(b"vote to your favorite ctf idx: ")
        # print(k)
        if b"hello world asdf" not in k or b"kill the flag" not in k or b"beat hex cart" not in k or pictures[0] not in k or pictures[1] not in k or pictures[2] not in k:
            p.close()
            return OFFLINE

        p.sendline(b"0")

        p.sendlineafter(b": ", b"4")
        if b"<0> " + b"a"*30 not in p.recv(1024):
            p.close()
            return OFFLINE

        # pause()
        p.close()
        return ONLINE
    except Exception as e:
        print(e)
        p.close()
        return OFFLINE

# testcase2 : vote testing ---------------------------------------


def testcase2(ip):
    p = remote(ip, 13337)
    try:
        add(p, 0, b"test", [b"a", b"b", b"c"])
        add(p, 1, b"user", [b"d", b"e", b"f"])
        add(p, 2, b"flag", [b"g", b"h", b"i"])

        # 0 -> 4, 1 -> 3, 2 -> 4 => 0 is the winner
        vote(p, 0)
        vote(p, 1)
        vote(p, 2)
        vote(p, 2)
        vote(p, 1)
        vote(p, 1)
        vote(p, 0)
        vote(p, 0)
        vote(p, 0)
        vote(p, 2)
        vote(p, 2)
        vote(p, 2)

        p.sendlineafter(b"input: ", b"4")
        k = p.recv(1024)
        # print(k)
        if b"<2> flag" not in k:
            p.close()
            return OFFLINE

        p.close()
        return ONLINE
    except:
        p.close()
        return OFFLINE

# testcase3 : delete succefully handled ---------------------------------------


def testcase3(ip):
    check = 0
    p = remote(ip, 13337)
    try:
        add(p, 0, b"test", [b"a", b"b", b"c"])
        add(p, 1, b"user", [b"d", b"e", b"f"])
        add(p, 2, b"flag", [b"g", b"h", b"i"])

        # delete(p, 1)

        p.sendlineafter(b": ", b"1")
        p.sendlineafter(b"? ", b"1")

        check = 1

        p.sendlineafter(b"? ", b"test")

        p.close()
        return OFFLINE
    except Exception as e:
        print(e)
        p.close()
        if check:
            return ONLINE
        return OFFLINE

# testcase4 : test invalid vote idx ---------------------------------------


def testcase4(ip):
    p = remote(ip, 13337)
    try:
        add(p, 0, b"test", [b"a", b"b", b"c"])
        add(p, 1, b"user", [b"d", b"e", b"f"])
        add(p, 2, b"flag", [b"g", b"h", b"i"])

        # delete(p, 1)

        vote(p, 0)
        vote(p, 1)
        vote(p, 2)
        vote(p, 3)

        if b"?\n" not in p.recv(1024):
            p.close()
            return OFFLINE

        p.close()
        return ONLINE
    except:
        p.close()
        return OFFLINE

# testcase5 : vote, delete, and exit ---------------------------------------


def testcase5(ip):
    p = remote(ip, 13337)
    try:
        add(p, 0, b"test", [b"a", b"b", b"c"])

        vote(p, 0)
        delete(p, 0)
        p.sendlineafter(b"input: ", b"4")

        if b"winner removed? you shouldn't do that...\n" not in p.recv(1024):
            p.close()
            return OFFLINE

        p.close()
        return ONLINE
    except:
        p.close()
        return OFFLINE

# testcase6 : checksum number is valid on vote ---------------------------------------


def testcase6(ip):
    check = 0
    p = remote(ip, 13337)
    try:
        add(p, 0, b"acsctf", [b"1", b"2", b"3"], True, -
            0x1, -0x908, b"A"*0x900 + p64(0x1337133713371337))

        check = 1

        vote(p, 0)

        k = p.recv(1024)
        print(k)
        if b"I know what you r doing\n" in k:
            p.close()
            return OFFLINE

        p.close()
        return ONLINE
    except:
        p.close()
        if check == 0:
            return ONLINE
        return OFFLINE

# testcase7 : checksum number is valid on delete ---------------------------------------


def testcase7(ip):
    check = 0
    p = remote(ip, 13337)
    try:
        add(p, 0, b"acsctf", [b"1", b"2", b"3"], True, -
            0x1, -0x908, b"A"*0x900 + p64(0x1337133713371337))

        check = 1

        delete(p, 0)

        k = p.recv(1024)
        print(k)
        if b"I know what you r doing\n" in k:
            p.close()
            return OFFLINE

        p.close()
        return ONLINE
    except Exception as e:
        print(e)
        p.close()
        if check == 0:
            return ONLINE
        return OFFLINE


def testvuln(ip):
    check = 0
    try:
        p = remote(ip, 13337)

        p.sendlineafter(b": ", b"1")
        p.sendlineafter(b"? ", str(0).encode())
        p.sendlineafter(b"? ", b"acsctf")

        p.sendlineafter(b"? ", str(3).encode())
        for topic in [b"1", b"2", b"3"]:
            p.sendlineafter(b"topic> ", topic)

        p.sendlineafter(b"? ", b"y")
        p.sendlineafter(b"? ", str(-0x1).encode())
        p.sendlineafter(b"? ", str(-0x1).encode())

        check = 1

        p.recv(1024)

        p.close()
        return ONLINE
    except:
        if check == 0:
            return OFFLINE
        return PATCHED


def check_status(ip):
    print("check 1")
    if testcase1(ip) == OFFLINE:
        return OFFLINE
    print("check 2")
    if testcase2(ip) == OFFLINE:
        return OFFLINE
    print("check 3")
    if testcase3(ip) == OFFLINE:
        return OFFLINE
    print("check 4")
    if testcase4(ip) == OFFLINE:
        return OFFLINE
    print("check 5")
    if testcase5(ip) == OFFLINE:
        return OFFLINE
    print("check 6")
    if testcase6(ip) == OFFLINE:
        return OFFLINE
    print("check 7")
    if testcase7(ip) == OFFLINE:
        return OFFLINE
    print("check vulnerability")
    return testvuln(ip)


if __name__ == "__main__":
    print(check_status("0"))
    # print(check_status("180.210.119.20"))
