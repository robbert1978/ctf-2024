import gdb


for address in range(0x117c6000, 0x117c6000+0x1000*0x20, 0x1000):
    gdb.execute(f"p2v {hex(address)}")
