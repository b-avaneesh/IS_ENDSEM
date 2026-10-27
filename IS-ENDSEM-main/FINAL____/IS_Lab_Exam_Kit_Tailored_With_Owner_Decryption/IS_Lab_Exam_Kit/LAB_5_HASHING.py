"""LAB 5 - HASHING, PERFORMANCE, COLLISIONS AND SOCKET INTEGRITY

Only the Python standard library is required.
Run the server and client in two terminals:
    python LAB_5_HASHING.py server
    python LAB_5_HASHING.py client
"""

import hashlib
import json
import random
import socket
import string
import sys
import time


# ---------------------------------------------------------------------------
# Q1: USER-DEFINED 32-BIT HASH
# ---------------------------------------------------------------------------
def custom_hash(text):
    hash_value = 5381
    for character in text:
        # Multiply by 33, add ASCII/Unicode value, mix bits, keep 32 bits.
        hash_value = (hash_value * 33 + ord(character)) & 0xFFFFFFFF
        hash_value = (hash_value ^ (hash_value >> 13)) & 0xFFFFFFFF
    return hash_value


def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


# STANDARD EXAM INTERFACE - SAME HASHING NAME USED IN OTHER LABS/TEMPLATE.
def hash_data(data, algorithm="sha256"):
    """Hash str/bytes using custom, MD5, SHA-1 or SHA-256."""
    if algorithm.lower() == "custom":
        text = data.decode() if isinstance(data, bytes) else data
        return custom_hash(text)
    raw = data.encode() if isinstance(data, str) else data
    name = algorithm.lower().replace("-", "")
    return hashlib.new(name, raw).hexdigest()


def verify_hash(text, expected_hash, algorithm="sha256"):
    actual_hash = hash_data(text, algorithm)
    return actual_hash == expected_hash


# ---------------------------------------------------------------------------
# Q3: PERFORMANCE AND COLLISION EXPERIMENT
# ---------------------------------------------------------------------------
def random_dataset(count=100, length=20):
    alphabet = string.ascii_letters + string.digits
    return ["".join(random.choice(alphabet) for _ in range(length)) for _ in range(count)]


def hash_performance_and_collisions(count=100):
    if not 50 <= count <= 100:
        raise ValueError("Manual asks for 50 to 100 strings")
    data = random_dataset(count)
    algorithms = {
        "MD5": lambda value: hashlib.md5(value.encode()).hexdigest(),
        "SHA-1": lambda value: hashlib.sha1(value.encode()).hexdigest(),
        "SHA-256": lambda value: hashlib.sha256(value.encode()).hexdigest(),
    }
    results = {}
    for name, function in algorithms.items():
        start = time.perf_counter()
        hashes = [function(value) for value in data]
        elapsed = time.perf_counter() - start
        collisions = len(hashes) - len(set(hashes))
        results[name] = {"time": elapsed, "collisions": collisions}
        print(name, "time:", elapsed, "seconds; collisions:", collisions)
    return results


# ---------------------------------------------------------------------------
# Q2 + ADDITIONAL Q1: SOCKET CLIENT/SERVER INTEGRITY CHECK
# A JSON line carries one or many message parts. The server reassembles them.
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 5000


def receive_json_line(connection):
    data = b""
    while not data.endswith(b"\n"):
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())


def send_json_line(connection, value):
    connection.sendall((json.dumps(value) + "\n").encode())


def run_server(host=HOST, port=PORT):
    """Start this first. Press Ctrl+C to stop it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        print("Hash server listening on", host, port)
        while True:
            connection, address = server.accept()
            with connection:
                request = receive_json_line(connection)
                message = "".join(request["parts"])
                server_hash = sha256_hash(message)
                send_json_line(connection, {"hash": server_hash})
                print("Received from", address, ":", message)
                print("SHA-256:", server_hash)


def split_message(message, number_of_parts=3):
    part_size = max(1, (len(message) + number_of_parts - 1) // number_of_parts)
    return [message[i:i + part_size] for i in range(0, len(message), part_size)]


def run_client(message, tamper=False, host=HOST, port=PORT):
    """Set tamper=True to demonstrate that hash verification fails."""
    original_hash = sha256_hash(message)
    sent_message = message + " CHANGED" if tamper else message
    parts = split_message(sent_message)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((host, port))
        send_json_line(client, {"parts": parts})
        response = receive_json_line(client)

    server_hash = response["hash"]
    print("Local hash: ", original_hash)
    print("Server hash:", server_hash)
    if original_hash == server_hash:
        print("Integrity verified: data was not changed")
        return True
    print("Integrity failed: corruption/tampering detected")
    return False


def simple_demo():
    text = input("Enter text: ")
    print("Custom 32-bit hash:", custom_hash(text))
    print("MD5:   ", md5_hash(text))
    print("SHA-1: ", sha1_hash(text))
    print("SHA-256:", sha256_hash(text))
    hash_performance_and_collisions(100)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "server":
        run_server()
    elif len(sys.argv) > 1 and sys.argv[1].lower() == "client":
        user_message = input("Enter message: ")
        change = input("Simulate tampering? (y/n): ").lower() == "y"
        run_client(user_message, change)
    else:
        simple_demo()
