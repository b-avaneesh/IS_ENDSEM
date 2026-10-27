"""RSA signature client/server in one file. Requires PyCryptodome."""

import json
import socket
import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

HOST, PORT = "127.0.0.1", 5001


def generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def sign_data(data, private_key):
    return pkcs1_15.new(private_key).sign(SHA256.new(data.encode()))


def verify_signature(data, signature, public_key):
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data.encode()), signature)
        return True
    except (ValueError, TypeError):
        return False


def run_server():
    with socket.socket() as server:
        server.bind((HOST, PORT))
        server.listen(1)
        print("Server waiting...")
        connection, _ = server.accept()
        with connection:
            package = json.loads(connection.recv(10000).decode())
            public_key = RSA.import_key(package["public_key"])
            signature = bytes.fromhex(package["signature"])
            valid = verify_signature(package["data"], signature, public_key)
            print("Received:", package["data"])
            print("Signature valid:", valid)
            connection.sendall(str(valid).encode())


def run_client():
    data = input("Enter data: ")
    public_key, private_key = generate_keys()
    package = {
        "data": data,
        "signature": sign_data(data, private_key).hex(),
        "public_key": public_key.export_key().decode(),
    }
    with socket.socket() as client:
        client.connect((HOST, PORT))
        client.sendall(json.dumps(package).encode())
        print("Server verification:", client.recv(100).decode())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "server":
        run_server()
    else:
        run_client()
