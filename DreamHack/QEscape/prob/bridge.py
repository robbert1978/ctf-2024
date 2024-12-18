#!/bin/python3
from string import ascii_lowercase, ascii_uppercase, digits
from random import choices
import os
import sys
import base64
import uuid

filename = str(uuid.uuid4())


def write(x):
    sys.stdout.write(x)
    sys.stdout.flush()


def readline():
    write("> ")
    return sys.stdin.readline().rstrip("\n")


def randstr(k):
    return ''.join(choices(ascii_lowercase+ascii_uppercase+digits, k=k))


def bridge():
    write("[+] Input Base64 encoded ELF\n")
    data = readline()

    if not data:
        write("[-] Error!\n")
        exit()

    try:
        elf = base64.b64decode(data)
    except:
        write("[-] decode error!\n")
        exit()

    write("[+] Copying ELF ..\n")
    workdir = "/tmp/%s" % filename
    os.mkdir(workdir)
    open(workdir+"/exploit", "wb+").write(elf)
    return workdir


def run(workdir):
    try:
        write("[+] Setting up Environment ..\n")
        os.chdir(workdir)
        os.mkdir("rootfs")
        os.system(
            "cd rootfs && zcat /home/robbert/CTF/DreamHack/QEscape/prob/rootfs.img.gz | cpio --extract")
        os.system("cp exploit rootfs/root/exploit")
        os.system("chmod 0777 rootfs/root/exploit")
        os.system(
            "cd rootfs && find . | cpio -H newc -o | gzip > /home/robbert/CTF/DreamHack/QEscape/prob/rootfs.img.gz")
        os.chdir("/home/robbert/CTF/DreamHack/QEscape/prob")
        write("[+] Booting QEMU ..\n")
        # os.system("./run.sh %s/rootfs.img.gz && rm -r %s" % (workdir, workdir))
        os.system(f"rm -rf {workdir}")
        write("Bye!\n")
        exit()
    except:
        os.system(f"rm -rf {workdir}")
        exit()


if __name__ == "__main__":
    run(bridge())
