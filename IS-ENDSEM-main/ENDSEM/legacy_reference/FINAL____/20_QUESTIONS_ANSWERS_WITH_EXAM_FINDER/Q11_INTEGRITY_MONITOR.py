# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - Replace the EduSecure role flow with two-terminal socket client/server execution.
# - Split a message into parts; the server reassembles them in order.
# - Server calculates MD5, SHA-1 and SHA-256 and returns SHA-256 to the client.
# - Include tampering plus a 50-100-string timing/collision comparison.
# =====================================================================
"""Multipart client/server hashing, tampering and performance."""

import hashlib

import json

import random

import socket

import string

import sys

import time

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

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

def split_message(message, number_of_parts=3):
    part_size = max(1, (len(message) + number_of_parts - 1) // number_of_parts)
    return [message[i:i + part_size] for i in range(0, len(message), part_size)]

SERVER_LOG = []


def run_server(host=HOST, port=PORT):
    from datetime import datetime
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port)); server.listen()
        print("Integrity server listening on", host, port)
        while True:
            connection, _ = server.accept()
            with connection:
                request = receive_json_line(connection)
                message = "".join(request["parts"])
                hashes = {"md5": md5_hash(message), "sha1": sha1_hash(message),
                          "sha256": sha256_hash(message)}
                SERVER_LOG.append({"message_id": request["message_id"], "hashes": hashes,
                                   "time": datetime.now().isoformat(timespec="seconds")})
                send_json_line(connection, hashes)


def run_client(message, tamper=False, host=HOST, port=PORT):
    original_hash = sha256_hash(message)
    parts = split_message(message)
    if tamper and parts: parts[0] += " CHANGED"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((host, port))
        send_json_line(client, {"message_id": str(time.time_ns()), "parts": parts})
        hashes = receive_json_line(client)
    print("MD5:", hashes["md5"]); print("SHA-1:", hashes["sha1"])
    print("SHA-256:", hashes["sha256"])
    print("Verified:", original_hash == hashes["sha256"])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "server": run_server()
    elif len(sys.argv) > 1 and sys.argv[1].lower() == "performance": hash_performance_and_collisions(100)
    else: run_client(input("Message: "), input("Tamper? (y/n): ").lower() == "y")
