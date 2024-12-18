
import gdb
import os


def add_all_folder(path):
    if path[-1] != '/':
        path += '/'
    gdb.execute('dir ' + path)
    dir = os.listdir(path)
    for i in dir:
        subfolder = path + i + '/'
        if os.path.isdir(subfolder):
            add_all_folder(subfolder)


# set $glibc_src_dir = "<glibc_src_dir>"
add_all_folder(gdb.parse_and_eval("$glibc_src_dir").string())
