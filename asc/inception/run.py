#!/usr/bin/python3 -u

import random
import string
import hashlib
import os
import signal
import sys
from datetime import datetime


addr = os.getenv("SOCAT_PEERADDR")


difficulty = os.getenv("POW_DIFFICULTY")
if difficulty == None:
    difficulty = 6
else:
    difficulty = int(difficulty)


def generate_challenge(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def verify_proof_of_work(challenge, nonce, difficulty):
    data = f"{challenge}{nonce}".encode()
    hash = hashlib.sha256(data).hexdigest()
    return hash.startswith('0' * difficulty)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main():

    signal.alarm(100)

    challenge = generate_challenge()
    print(f"challenge: {challenge}")
    try:
        nonce = input("answer: ")
    except EOFError:
        pass
    result = verify_proof_of_work(challenge, nonce, 5)

    if not result:
        print(f"[{now()}] {addr} {challenge} {nonce} - proof of work failed", file=sys.stderr)
        exit(-1)
    else:
        print(f"[{now()}] {addr} {challenge} {nonce} - proof of work succeed", file=sys.stderr)
    
    os.execl("/home/inception/portal", "/home/inception/portal")
    print(f"[{now()}] {addr} {challenge} {nonce} - failed to open portal", file=sys.stderr)
    exit(-1)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[{now()}] {addr} exception occured: {exc}", file=sys.stderr)
