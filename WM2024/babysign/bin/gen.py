import random
import sys
import string
import base64
import os


if __name__ == "__main__":
    code = input("Base64")
    code = code.encode()
    code = base64.b64decode(code)
    with open("/home/ctf/tmp/test.ll","wb+") as f:
        f.write(code)
        f.close()
    os.system("/usr/sbin/chroot --userspec=1000:1000 /home/ctf ./opt -load ./WMCTF.so -WMCTF -enable-new-pm=0 /tmp/test.ll")
    os.unlink("/home/ctf/tmp/test.ll")