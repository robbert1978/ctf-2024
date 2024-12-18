import struct
import os

# Change this to the path to vmlinux.
# The kernel image is parsed to calculate offsets in order to avoid adding an extra RELA
# VMLINUX_PATH="../../linux-5.19.17/vmlinux"
VMLINUX_PATH = "vmlinux"


# padding helpers
def padn(x, n):
    assert len(x) <= n
    if type(x) == str:
        x = x.encode()
    return x+(b'\0'*(n-len(x)))


def padw(x): return padn(x, 2)
def padd(x): return padn(x, 4)
def padq(x): return padn(x, 8)


half = padw
word = padd
addr = padq
off = padq

# struct helpers


class Elf64_Ehdr():
    def __init__(self):
        self.ei_class = b'\x02'  # 1 -> 32 bit, 2->64 bit
        self.ei_data = b'\x01'  # 1 ->LE, 2->BE
        self.ei_version = b'\x01'
        self.elf_abi = b'\0'
        self.e_type = b'\x01'  # 1->relocatable, 2->executable, 3->shared, 4->core
        self.e_machine = b'\x3e'  # 3->x86, 0x3e->x86_64
        self.e_version = b'\x01'
        self.e_entry = b''
        self.e_phoff = b''
        self.e_shoff = b''
        self.e_flags = b''  # ignored for x86
        self.e_ehsize = b'\x40'  # size of this header
        self.e_phentsize = b'\x38'
        self.e_phnum = b''
        self.e_shentsize = b'\x40'  # might be wrong?
        self.e_shnum = b''
        self.e_shstrndx = b''

    def __len__(self): return 0x40

    def create(self):
        d = b''
        e_ident = b'\x7fELF'+self.ei_class+self.ei_data+self.ei_version+self.elf_abi
        d += padn(e_ident, 16)
        d += half(self.e_type)
        d += half(self.e_machine)
        d += word(self.e_version)
        d += addr(self.e_entry)
        d += off(self.e_phoff)
        d += off(self.e_shoff)
        d += word(self.e_flags)
        d += half(self.e_ehsize)
        d += half(self.e_phentsize)
        d += half(self.e_phnum)
        d += half(self.e_shentsize)
        d += half(self.e_shnum)
        d += half(self.e_shstrndx)
        assert len(d) == 0x40
        return d


class Elf64_Phdr():
    def __init__(self, p_type):
        if type(p_type) == int:
            p_type = struct.pack('<I', p_type)
        self.p_type = p_type
        self.p_offset = b''
        self.p_vaddr = b''
        self.p_paddr = b''
        self.p_filesz = b''
        self.p_memsz = b''
        self.p_flags = b'\x07'  # RWX
        self.p_align = b'\x01'

    def __len__(self): return 0x38

    def create(self):
        d = b''
        d += word(self.p_type)
        d += word(self.p_flags)
        d += off(self.p_offset)
        d += addr(self.p_vaddr)
        d += addr(self.p_paddr)
        d += padq(self.p_filesz)
        d += padq(self.p_memsz)
        d += padq(self.p_align)
        assert len(d) == 0x38
        return d


class Elf64_Shdr():
    def __init__(self, sh_type):
        if type(sh_type) == int:
            sh_type = struct.pack("<I", sh_type)
        self.sh_name = b''
        self.sh_type = sh_type
        self.sh_flags = b''
        self.sh_addr = b''
        self.sh_offset = b''
        self.sh_size = b''
        self.sh_link = b''
        self.sh_info = b''
        self.sh_addralign = b'\x01'
        self.sh_entsize = b''

    def __len__(self): return 0x40

    def create(self):
        d = b''
        d += word(self.sh_name)
        d += word(self.sh_type)
        d += padq(self.sh_flags)
        d += addr(self.sh_addr)
        d += off(self.sh_offset)
        d += padq(self.sh_size)
        d += word(self.sh_link)
        d += word(self.sh_info)
        d += addr(self.sh_addralign)
        d += padq(self.sh_entsize)
        assert len(d) == 0x40
        return d


ehdr = Elf64_Ehdr()
ehdr.e_phentsize = b''
ehdr.e_shoff = None

# sh_null: the kernel requires sh_type==SHT_NULL, sh_size==0, sh_addr==0.
sections = [
    Elf64_Shdr(0),  # sh_null, null=0
    Elf64_Shdr(1),  # .text, progbits=1
    Elf64_Shdr(2),  # .symtab, symtab=1
    Elf64_Shdr(4),  # .rela.gnu.linkonce.this_module, rela=4
    Elf64_Shdr(3),  # .strtab, strtab=3
    Elf64_Shdr(1),  # .gnu.linkonce.this_module, progbits=1
]


do_init_mod_ret = os.popen("objdump --disassemble=do_init_module {}|grep call -A1|grep do_one_initcall -A1".format(
    VMLINUX_PATH)).read().split("\n")[1].split(":")[0]
# vermagic = os.popen(
#     "gdb -n -batch -ex 'p &vermagic' {} 2>/dev/null".format(VMLINUX_PATH)).read()

# print(vermagic)
# print("vermagic: '{}'".format(vermagic))

vermagic = '6.3.0 SMP preempt mod_unload '
strtab = b'.gnu.linkonce.this_module\0.modinfo\0'
# modinfo = b"license=GPL\0intree=\0retpoline=\0vermagic="+vermagic.encode() + \
#     b"\0\0"
# modinfo=b"license=gpl\0intree=y\0retpoline=y\0vermagic=5.19.17 smp preempt mod_unload \0\0"
modinfo = b''
strtab = modinfo+strtab


cur_snum = 0
ehdr.e_shnum = chr(len(sections))

cur_data_ptr = len(ehdr)

# struct module
#  .name: 0x018
this_module = b'\0'*0x18
# The data after the first \0 is the message passed to printk
this_module += b'hi\0:)\n\0'
this_module += b'\0'*(0x160-len(this_module))
this_module_base = cur_data_ptr
cur_data_ptr += len(this_module)


# SH_NULL
sections[cur_snum].sh_addralign = b''
cur_snum += 1

# build the payload

# get the offset from the return address from do_one_initcall to _printk by parsing vmlinux
do_init_mod_ret = os.popen("objdump --disassemble=do_init_module {}|grep call -A1|grep do_one_initcall -A1".format(
    VMLINUX_PATH)).read().split("\n")[1].split(":")[0]
printk = os.popen("nm {}|grep ' _printk$'".format(
    VMLINUX_PATH)).read().split(" ")[0]
a0 = int(do_init_mod_ret, 16)
a1 = int(printk, 16)
print("return address: "+do_init_mod_ret)
print("_printk address: "+printk)
print("offset: "+hex(a1-a0))
printk_offs = struct.pack("<I", a1-a0 & ((1 << 32) - 1))


# this payload may require changes for your system. On my kernel, we can get a pointer to this_module at [rpb-0x10]
# if something crashes, you can easily verify that the code is running by replacing this with \xcc and looking for the panic, or
# mov ax, 1; ret and looking for the warning message.

code = b'\xcc'

# currently using the 0x18 bytes before module.name. for a longer payload, jump elsewhere.
assert len(code) <= 0x18, "Payload is too long: %d > 0x18".format(len(code))

# .text
code_ptr = struct.pack("<Q", cur_data_ptr)
sections[cur_snum].sh_size = struct.pack(
    "<I", 0x200)  # len(ehdr)+len(struct module)
sections[cur_snum].sh_offset = struct.pack("<I", cur_data_ptr)
sections[cur_snum].sh_name = struct.pack(
    "<I", strtab.index(b"fo"))  # name doesnt matter
sections[cur_snum].sh_flags = b'\x06'  # ALLOC|EXECINSTR
code_idx = cur_snum
cur_snum += 1

# .symtab


def makesymtab(st_name, st_info, st_other, st_shndx, st_value, st_size):
    dat = struct.pack("<IBBHQQ", st_name, st_info,
                      st_other, st_shndx, st_value, st_size)
    assert len(dat) == 0x18
    return dat


symtab = b"\0"*0x18
# symbol is at offset 0 from the start of the .text section
symtab += makesymtab(0, 0, 0, code_idx, 0, 0)  # init

sections[cur_snum].sh_size = struct.pack("<I", len(symtab))
sections[cur_snum].sh_offset = struct.pack("<I", cur_data_ptr)
sections[cur_snum].sh_flags = b'\x02'  # ALLOC
sections[cur_snum].sh_entsize = b'\x18'
sections[cur_snum].sh_info = b'\x01'
sections[cur_snum].sh_name = struct.pack("<I", strtab.index(b"le"))
symtab_idx = cur_snum
cur_snum += 1


# .rela.gnu.linkonce.this_module
# elf64_rela: offset (within section), r_info, addend
def makerela(offset, info, addend=0): return struct.pack(
    "<QQQ", offset, info, addend)


# .init, symtab idx 1, direct 64-bit relocation
rela = makerela(0x138, (1 << 32) | 1)
# .exit, symtab idx 1, direct 64-bit relocation. `ret` is 22 bytes into our payload
rela += makerela(0x328, (1 << 32) | 1, 22)

sections[cur_snum].sh_size = struct.pack("<I", len(rela))
sections[cur_snum].sh_offset = struct.pack("<I", cur_data_ptr)
sections[cur_snum].sh_flags = b'\x40'  # SHF_INFO_LINK
sections[cur_snum].sh_link = struct.pack("<H", symtab_idx)
sections[cur_snum].sh_name = struct.pack("<I", strtab.index(
    b".linkonce.this_module"))  # name doesnt actually matter
rela_idx = cur_snum
cur_snum += 1

# .strtab
sections[cur_snum].sh_size = struct.pack("<I", len(strtab))
sections[cur_snum].sh_offset = struct.pack("<I", cur_data_ptr)
sections[cur_snum].sh_name = struct.pack("<I", strtab.index(b".modinfo"))
sections[cur_snum].sh_flags = b'\x02'  # ALLOC
strtab_idx = cur_snum
cur_snum += 1

# .gnu.linkonce.this_module
sections[cur_snum].sh_size = struct.pack(
    "<H", len(this_module) if len(this_module) > 0x180 else 0x200)
sections[cur_snum].sh_offset = struct.pack("<I", this_module_base)
sections[cur_snum].sh_flags = b'\x03'  # ALLOC|WRITE
sections[cur_snum].sh_name = struct.pack(
    "<I", strtab.index(b".gnu.linkonce.this_module"))
this_module_idx = cur_snum
cur_snum += 1

# ----- end of section headers -----

# (offset,size) of free space within struct module
# not complete, but these are some of the bigger contiguous regions
module_freespace_map = [
    (0, 0x18),  # 0: code
    (0x34,   28),  # 1: rela
    (0x60, 0x38),  # 2: symtab
    (0xb0, 0x80),  # 3: strtab
]


def overlap_region(map_idx, sh_idx, data, pad=True, off=0):
    def nzpad(x, y): return x+b'Z'*(y-len(x))
    global this_module
    r = module_freespace_map[map_idx]
    print("{}: {} used out of {} ({} free)".format(
        map_idx, len(data), r[1], r[1]-len(data)))
    if pad:
        data = nzpad(data, r[1])
    assert len(data) <= r[1]
    this_module = this_module[:r[0]]+data+this_module[r[0]+len(data):]
    sections[sh_idx].sh_offset = struct.pack("<I", this_module_base+r[0]+off)


# point this_module rela section to the this_module section
sections[rela_idx].sh_info = struct.pack("<H", this_module_idx)
# symtab -- overlap 0 entry with something else
ehdr.e_shstrndx = struct.pack("<H", strtab_idx)
overlap_region(0, code_idx, code)
overlap_region(2, rela_idx, rela)
# first entry of symtab is ignored
overlap_region(1, symtab_idx, symtab[0x18:], off=-0x18)
overlap_region(3, strtab_idx, strtab)
# fixup shdr offset
ehdr.e_shoff = struct.pack("<I", cur_data_ptr)
# point symtab to the strtab section
sections[symtab_idx].sh_link = struct.pack("<H", strtab_idx)

# build the output
filedata = ehdr.create()
print(f"Ehdr's len: {len(filedata)}")
filedata += this_module
for i in sections:
    filedata += i.create()
print("filesize: {}".format(len(filedata)))
open("hi.ko", "wb").write(filedata)

# -- assert that we don't overlap with known unsafe fields


def r(a, s=8): return filedata[this_module_base +
                               a:this_module_base+a+s] == b'\0'*s


def d(a, s=8): return filedata[this_module_base+a:this_module_base+a+s].hex()


assert r(0x98, 24), d(0x98, 24)
assert r(0x130, 0x20), d(0x130, 0x20)
assert r(0x150, 0x40), d(0x150, 0x40)
assert r(0x190, 0x10), d(0x190, 0x10)


def file_to_c_hex_array(filename):
    try:
        with open(filename, 'rb') as f:
            data = f.read()

        # Convert the binary data to a list of hex values
        hex_array = ', '.join(f'0x{byte:02X}' for byte in data)

        # Format it as a C-style array
        c_hex_array = f"unsigned char data[] = {{\n    {hex_array}\n}};"

        print(c_hex_array)
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error: {str(e)}"


file_to_c_hex_array('hi.ko')
