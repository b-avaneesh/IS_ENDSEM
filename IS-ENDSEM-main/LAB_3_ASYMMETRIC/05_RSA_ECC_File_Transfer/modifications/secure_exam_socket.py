# simple_exam.py
# Simplified classroom demo: TCP sockets + RSA/AES + SHA-512 +
# ElGamal signatures + Paillier encrypted score totals.
# Demo parameters only; NOT secure for real exams.

import socket
import json
import os
import hashlib
import secrets
from math import gcd, lcm

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = 5000
ANSWER_KEY = ["A", "B", "C"]

# ----- RSA keys -----
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()


def encrypt_message(message):
    key = os.urandom(32)  # AES-256
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key, iv, ciphertext


def decrypt_message(encrypted_key, iv, ciphertext):
    key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


# ----- SHA-512 -----
def hash_message(message):
    return hashlib.sha512(message.encode()).digest()


# ----- ElGamal signature: tiny educational parameters -----
P, G, X = 467, 2, 127
Y = pow(G, X, P)


def sign(message):
    h = int.from_bytes(hash_message(message), "big") % (P - 1)
    while True:
        k = secrets.randbelow(P - 2) + 1
        if gcd(k, P - 1) == 1:
            break
    r = pow(G, k, P)
    s = (pow(k, -1, P - 1) * (h - X * r)) % (P - 1)
    return [r, s]


def verify(message, signature):
    r, s = signature
    if not (0 < r < P and 0 <= s < P - 1):
        return False
    h = int.from_bytes(hash_message(message), "big") % (P - 1)
    left = (pow(Y, r, P) * pow(r, s, P)) % P
    right = pow(G, h, P)
    return left == right


# ----- Paillier: tiny educational parameters -----
PA, PB = 17, 19
N = PA * PB
N2 = N * N
PG = N + 1
LAM = lcm(PA - 1, PB - 1)
MU = pow(LAM, -1, N)


def paillier_encrypt(m):
    while True:
        r = secrets.randbelow(N - 1) + 1
        if gcd(r, N) == 1:
            break
    return (pow(PG, m, N2) * pow(r, N, N2)) % N2


def paillier_decrypt(c):
    u = pow(c, LAM, N2)
    return (((u - 1) // N) * MU) % N


def server():
    encrypted_total = paillier_encrypt(0)

    with socket.socket() as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Server listening on", HOST, PORT)

        while True:
            conn, _ = s.accept()
            with conn:
                request = json.loads(conn.recv(4096).decode())
                student_id = str(request.get("student_id", "")).strip()
                answers = request.get("answers", [])

                if not student_id or not isinstance(answers, list) or len(answers) != 3:
                    response = {"error": "Send student_id and exactly 3 answers."}
                else:
                    answers = [str(a).strip().upper() for a in answers]
                    score = sum(1 for i in range(3) if answers[i] == ANSWER_KEY[i])
                    message = json.dumps(
                        {"student_id": student_id, "answers": answers},
                        sort_keys=True
                    )

                    digest = hash_message(message).hex()
                    signature = sign(message)

                    encrypted_key, iv, ciphertext = encrypt_message(message)
                    recovered = decrypt_message(encrypted_key, iv, ciphertext)

                    # Verify the hash/signature against the recovered plaintext.
                    hash_ok = hash_message(recovered).hex() == digest
                    signature_ok = verify(recovered, signature)

                    encrypted_score = paillier_encrypt(score)
                    encrypted_total = (
                        encrypted_total * encrypted_score
                    ) % N2

                    response = {
                        "message": "Submission processed",
                        "student_id": student_id,
                        "score": score,
                        "sha512": digest,
                        "signature_valid": signature_ok,
                        "hash_valid": hash_ok,
                        "encrypted_ballot_hex": ciphertext.hex(),
                        "encrypted_aes_key_hex": encrypted_key.hex(),
                        "encrypted_class_total": str(encrypted_total)
                    }

                conn.sendall(json.dumps(response).encode())


def client():
    student_id = input("Student ID: ").strip()
    answers = [
        input("Answer to Q1 (A/B/C/D): "),
        input("Answer to Q2 (A/B/C/D): "),
        input("Answer to Q3 (A/B/C/D): ")
    ]

    request = {"student_id": student_id, "answers": answers}

    with socket.socket() as s:
        s.connect((HOST, PORT))
        s.sendall(json.dumps(request).encode())
        response = json.loads(s.recv(8192).decode())

    print(json.dumps(response, indent=2))


if __name__ == "__main__":
    mode = input("Run server or client? (s/c): ").strip().lower()
    if mode == "s":
        server()
    elif mode == "c":
        client()
    else:
        print("Enter s or c.")
