from base64 import b64decode
from Crypto.Cipher import AES
from hashlib import sha256
from Crypto.Util.Padding import unpad
import os


def sus_b64_decode(inp):
    inp = inp[::-1]
    inp = inp.replace(b'-', b'C').replace(b'_', b'E')
    dec = ''
    try:
        dec = b64decode(inp)
    except:
        dec = b64decode(inp + b'==')
    return dec


with open('exported_object/data', 'rb') as f:
    data = f.read()
    data = sus_b64_decode(data)
    # print(data)


# from file 'data'
found_key = sus_b64_decode(
    b'gWJNVVxUDVFFGNDNjQqZDSKJmQS9WUphXRYd1LPNnd-NXeQVGdW5_bQJ2SWN2ZuVndtVzdhFjb3ZTZnhTdLFlZ')

encrypted_key = b64decode(found_key)

machinename = "administrator".lower()
username = 'win-ho5dpb1fvnd'.lower()

aes_key = f"0009190924" + username + machinename
aes_key = sha256(aes_key.encode()).digest()
iv = encrypted_key[:16]
aes = AES.new(aes_key, AES.MODE_CBC, iv)
masterKey = aes.decrypt(encrypted_key[16:])
masterKey = unpad(masterKey, 16)
print('Master key: ', masterKey)

# trying to decrypt flag


def dec_data(filename):
    with open(f'exported_object/{filename}', 'rb') as f:
        data = f.read()
        data = sus_b64_decode(data)
        iv = data[:16]
        content = data[16:]
        aes_key = sha256(masterKey).digest()
        aes = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(aes.decrypt(content), 16)


list_dir = os.listdir("exported_object")
for dir_name in list_dir:
    if dir_name not in ["data", 'logs', 'logs(1)'] and '(1)' not in dir_name:
        if b"flag" not in sus_b64_decode(dir_name.encode()):
            continue
        print(sus_b64_decode(dir_name.encode()), dec_data(dir_name))
