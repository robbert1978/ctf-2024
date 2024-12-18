#!/usr/bin/env python3

import subprocess
import sys
import tempfile

with tempfile.NamedTemporaryFile() as f:
    try:
        print('Length:')
        n = int(input())
        if n > 0x4000:
            exit()

        print('JS script:')
        b = b''
        for i in range(n):
            b += sys.stdin.buffer.read(1)

        f.write(b)
        f.flush()

        subprocess.run(['timeout', '30', '/home/ctf/d8', f.name], stderr=subprocess.DEVNULL)
    except:
        exit()