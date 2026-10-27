"""Hash client/server in one file. Run with argument server or client."""

import hashlib
import socket
import sys

HOST, PORT = "127.0.0.1", 5000


def hash_data(data, algorithm="sha256"):
    return hashlib.new(algorithm.replace("-", ""), data.encode()).hexdigest()


def verify_hash(data, expected_hash, algorithm="sha256"):
    return hash_data(data, algorithm) == expected_hash


def run_server():
    with socket.socket() as server:
        server.bind((HOST, PORT))
        server.listen(1)
        print("Server waiting...")
        connection, _ = server.accept()
        with connection:
            data = connection.recv(4096).decode()
            connection.sendall(hash_data(data).encode())
            print("Received:", data)


def run_client():
    data = input("Enter message: ")
    with socket.socket() as client:
        client.connect((HOST, PORT))
        client.sendall(data.encode())
        server_hash = client.recv(4096).decode()
    print("Server hash:", server_hash)
    print("Verified:", verify_hash(data, server_hash))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "server":
        run_server()
    else:
        run_client()
