#! /usr/bin/python3
import os
import sys
import subprocess
from threading import Thread
from shutil import copy
import uuid

def socket_print(string):
    print("=====", string, flush=True)

def run_challenge(filename):
    socket_print("start complete!")
    try: 
        cmd = "./ir2bin.sh"
        subprocess.run(cmd, shell=True, timeout=60)
    except subprocess.CalledProcessError as e:
        socket_print("stopping")
        clean_file(filename)
        pass

    socket_print("run binary")
    try: 
        subprocess.run("./hello", shell=True, timeout=60)
    except subprocess.CalledProcessError as e:
        socket_print("stopping")
        clean_file(filename)
        pass

def get_filename():
    return "./tmp/{}".format(uuid.uuid4().hex)

def clean_file(filename):
    socket_print("cleaning")
    subprocess.run("rm -r ../../"+filename, shell=True, timeout=60)

def mkdir(path):
	folder = os.path.exists(path)
	if not folder:                  
		os.makedirs(path)          
	else:
		socket_print("There is this folder!")

def input_code(filename):
    current_directory = os.getcwd()
    new_directory = current_directory + "/" + filename
    os.chdir(new_directory)
    socket_print("current: " + current_directory)
    socket_print("new: " + new_directory)

    with open('./hello.ugo', 'w') as file:
        print("input code: ")
        print("\tinput \"end\" to stop")
        while True:
            line = input()
            if line[:3] != "end": 
                file.write(line+"\n")
            else:
                break

def copy_file(filename):
    mkdir(filename)
    copy("/home/ctf/ugo", filename+"/ugo")
    copy("/home/ctf/hello.ugo", filename+"/hello.ugo")
    copy("/home/ctf/ir2bin.sh", filename+"/ir2bin.sh")

def check(filename):
    while True:
        if sys.stdout.closed:
            clean_file(filename)
            socket_print("Cleaned up directory:")

def main():
    filename = get_filename()
    print("Working path: "+filename)
    Thread(target=check,args=filename)
    copy_file(filename)
    input_code(filename)
    run_challenge(filename)
    clean_file(filename)

if __name__ == "__main__":
    main()