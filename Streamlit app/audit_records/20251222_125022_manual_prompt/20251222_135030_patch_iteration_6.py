
# SECURITY: Proper socket configuration
# - Use unique ports or proper port management
# - Set SO_REUSEADDR carefully
# - Validate port availability before binding

import socket

port = int(input("Enter port number: "))
host = "0.0.0.0"

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Use with caution
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Use with caution
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Use with caution
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Use with caution
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Use with caution
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Use with caution
server_socket.bind((host, port))
server_socket.listen(5)


conn, addr = server_socket.accept()


conn.close()
server_socket.close()