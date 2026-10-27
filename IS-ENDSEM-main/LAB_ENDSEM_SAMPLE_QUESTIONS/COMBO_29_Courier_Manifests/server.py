import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import socket
import threading
from pathlib import Path
from datetime import datetime

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Courier Manifests: Labs 1, 2, 3, 5, 6, 7, 8. Lab 4 excluded.
# Standalone teaching example. See PRACTICE.txt for scope and limitations.
HOST, PORT = "127.0.0.1", 5129
BLOCK_CIPHER, KEY_BYTES = DES, 8
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "writer": {"password": "write123", "role": "writer"},
    "reader": {"password": "read123", "role": "reader"},
    "auditor": {"password": "audit123", "role": "auditor"},
}
REPORTS = {}
AUDIT_FILE = Path(__file__).with_name("audit.log")
LOCK = threading.RLock()

SERVER_RSA = RSA.generate(2048)

def wrap_key(key):
    return b64(PKCS1_OAEP.new(SERVER_RSA.publickey()).encrypt(key))

def unwrap_key(wrapped):
    return PKCS1_OAEP.new(SERVER_RSA).decrypt(unb64(wrapped))

# Textbook ElGamal signature, deliberately tiny exam parameters.
SIG_P, SIG_G = 467, 2
USER_SIGNING_KEYS = {u: secrets.randbelow(SIG_P - 3) + 2 for u in USERS}
USER_VERIFY_KEYS = {u: pow(SIG_G, x, SIG_P) for u, x in USER_SIGNING_KEYS.items()}

def sign_content(username, content):
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    k = secrets.randbelow(SIG_P - 2) + 1
    while math.gcd(k, SIG_P - 1) != 1:
        k = secrets.randbelow(SIG_P - 2) + 1
    r = pow(SIG_G, k, SIG_P)
    s = ((value - USER_SIGNING_KEYS[username] * r) * pow(k, -1, SIG_P - 1)) % (SIG_P - 1)
    return [r, s]

def verify_signature(username, content, signature):
    r, s = signature
    if not (0 < r < SIG_P and 0 <= s < SIG_P - 1):
        return False
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    y = USER_VERIFY_KEYS[username]
    return pow(SIG_G, value, SIG_P) == pow(y, r, SIG_P) * pow(r, s, SIG_P) % SIG_P

# Raw textbook RSA has multiplicative homomorphism; RSA-OAEP does NOT.
HOM_RSA = RSA.generate(1024)

def homomorphic_demo(a, b):
    if not (0 <= a < HOM_RSA.n and 0 <= b < HOM_RSA.n):
        raise ValueError("Use nonnegative integers below the modulus")
    ca, cb = pow(a, HOM_RSA.e, HOM_RSA.n), pow(b, HOM_RSA.e, HOM_RSA.n)
    combined = ca * cb % HOM_RSA.n
    return {"operation": "multiplication modulo n", "encrypted_a": str(ca),
            "encrypted_b": str(cb), "encrypted_result": str(combined),
            "decrypted_result": pow(combined, HOM_RSA.d, HOM_RSA.n),
            "expected": a * b % HOM_RSA.n}

from phe import paillier
# Public-key encrypted hash/index. The key owner decrypts to compare.
# Randomized ciphertexts cannot be compared directly. This is NOT PEKS.
SEARCH_PUBLIC, SEARCH_PRIVATE = paillier.generate_paillier_keypair(n_length=1024)
SEARCH_INDEX = []

def add_to_index(report_id, content):
    # Prefix byte preserves leading zeros when converting back to text.
    id_number = int.from_bytes(b"\x01" + report_id.encode(), "big")
    for word in words(content):
        number = int.from_bytes(hashlib.sha256(word.encode()).digest(), "big")
        SEARCH_INDEX.append((SEARCH_PUBLIC.encrypt(number), SEARCH_PUBLIC.encrypt(id_number)))

def search_reports(query):
    number = int.from_bytes(hashlib.sha256(query.encode()).digest(), "big")
    found = set()
    for enc_word, enc_id in SEARCH_INDEX:
        if SEARCH_PRIVATE.decrypt(enc_word) == number:
            value = SEARCH_PRIVATE.decrypt(enc_id)
            found.add(value.to_bytes((value.bit_length() + 7) // 8, "big")[1:].decode())
    return sorted(found)

def digest_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def letters_only_upper(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

def autokey_encrypt(plaintext, seed_key):
    seed_key = seed_key.upper()
    running_key = seed_key + letters_only_upper(plaintext)
    result, k = [], 0
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(running_key[k]) - ord('A')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)

def autokey_decrypt(ciphertext, seed_key):
    seed_key = seed_key.upper()
    running_key = list(seed_key)
    result, k = [], 0
    for ch in ciphertext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(running_key[k]) - ord('A')
            plain_letter_upper = chr((ord(ch) - base - shift) % 26 + ord('A'))
            running_key.append(plain_letter_upper)
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = autokey_encrypt(text, "H")
    decrypted = autokey_decrypt(encrypted, "H")
    return {"algorithm": "Autokey", "ciphertext": encrypted, "decrypted_text": decrypted}

def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def send_json(stream, obj):
    stream.write((json.dumps(obj) + "\n").encode())
    stream.flush()

def recv_json(stream):
    line = stream.readline()
    return json.loads(line.decode()) if line else None

def symmetric_encrypt(key, text):
    iv = get_random_bytes(BLOCK_CIPHER.block_size)
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(text.encode(), BLOCK_CIPHER.block_size))

def symmetric_decrypt(key, iv, ciphertext):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_CIPHER.block_size).decode()

def words(text):
    return set(re.findall(r"[^\W_]+", text.casefold()))

def signed_text(report_id, author, content):
    # Bind the document ID and author as well as the content to the signature.
    return json.dumps([report_id, author, content], ensure_ascii=False)

def audit(username, role, action, result, detail=""):
    record = {"time": datetime.now().isoformat(timespec="seconds"),
              "username": username, "role": role, "action": action,
              "result": result, "detail": detail}
    with LOCK:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

def has_permission(role, action):
    permissions = {
        "admin": {"upload", "get", "search", "audit", "list", "verify", "classical", "homomorphic"},
        "writer": {"upload", "get", "search", "list", "classical", "homomorphic"},
        "reader": {"search", "list"},
        "auditor": {"audit", "list", "verify"},
    }
    return action in permissions.get(role, set())

def open_report(report_id):
    item = REPORTS[report_id]
    key = unwrap_key(item["wrapped_key"])
    content = symmetric_decrypt(key, unb64(item["iv"]), unb64(item["ciphertext"]))
    valid = (digest_text(content) == item["digest"] and
             verify_signature(item["author"], signed_text(report_id, item["author"], content), item["signature"]))
    return content, valid

def verify_report(report_id):
    if report_id not in REPORTS:
        return False, "Document not found"
    try:
        _, valid = open_report(report_id)
        return valid, "Integrity and signature valid" if valid else "Verification failed"
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False, "Verification failed"

def handle_request(username, role, req):
    action = req.get("action", "")
    if not has_permission(role, action):
        audit(username, role, action, "DENIED")
        return {"status": "error", "message": "Permission denied for this role"}
    try:
        # Keep a whole request atomic, including duplicate check and index update.
        with LOCK:
            if action == "upload":
                report_id = str(req.get("report_id", "")).strip()
                content = str(req.get("content", ""))
                if not report_id or len(report_id.encode()) > 64 or not content:
                    return {"status": "error", "message": "ID (1-64 bytes) and content required"}
                if report_id in REPORTS:
                    return {"status": "error", "message": "Document ID already exists"}
                key = get_random_bytes(KEY_BYTES)
                iv, ciphertext = symmetric_encrypt(key, content)
                item = {"iv": b64(iv), "ciphertext": b64(ciphertext),
                        "wrapped_key": wrap_key(key), "digest": digest_text(content),
                        "signature": sign_content(username, signed_text(report_id, username, content)),
                        "author": username}
                add_to_index(report_id, content)
                REPORTS[report_id] = item
                audit(username, role, action, "SUCCESS", report_id)
                return {"status": "ok", "message": "Document encrypted, signed and indexed", "report_id": report_id}
            if action == "get":
                report_id = str(req.get("report_id", ""))
                if report_id not in REPORTS:
                    return {"status": "error", "message": "Document not found"}
                content, valid = open_report(report_id)
                if not valid:
                    return {"status": "error", "message": "Integrity/signature verification failed"}
                audit(username, role, action, "SUCCESS", report_id)
                return {"status": "ok", "content": content, "digest": digest_text(content), "signature_verified": True}
            if action == "search":
                tokens = words(str(req.get("query", "")))
                if len(tokens) != 1:
                    return {"status": "error", "message": "Enter one search word"}
                return {"status": "ok", "report_ids": search_reports(tokens.pop())}
            if action == "list":
                return {"status": "ok", "report_ids": sorted(REPORTS)}
            if action == "audit":
                lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines() if AUDIT_FILE.exists() else []
                return {"status": "ok", "logs": [json.loads(line) for line in lines[-100:]]}
            if action == "verify":
                valid, message = verify_report(str(req.get("report_id", "")))
                return {"status": "ok", "verified": valid, "message": message}
            if action == "classical":
                return {"status": "ok", **classical_demo(str(req.get("text", "")))}
            if action == "homomorphic":
                return {"status": "ok", **homomorphic_demo(int(req.get("a", 0)), int(req.get("b", 0)))}
    except Exception as exc:
        audit(username, role, action, "ERROR", type(exc).__name__)
        return {"status": "error", "message": str(exc)}
    return {"status": "error", "message": "Unknown action"}

def client_thread(conn, addr):
    username = "unknown"
    role = "unknown"
    try:
        with conn, conn.makefile("rwb") as stream:
            login = recv_json(stream)
            if not login:
                return
            username = str(login.get("username", ""))
            user = USERS.get(username)
            if not user or not hmac.compare_digest(str(login.get("password", "")), user["password"]):
                audit(username, "unknown", "login", "FAILED")
                send_json(stream, {"status": "error", "message": "Invalid login"})
                return
            role = user["role"]
            audit(username, role, "login", "SUCCESS")
            send_json(stream, {"status": "ok", "message": "Login successful", "role": role})
            while True:
                req = recv_json(stream)
                if req is None or req.get("action") == "quit":
                    break
                response = handle_request(username, role, req)
                send_json(stream, response)
    except (ConnectionError, json.JSONDecodeError, OSError, AttributeError, UnicodeError):
        pass
    finally:
        print(f"Connection closed: {addr} ({username}/{role})")


def main():
    print(f"Server listening on {HOST}:{PORT}")
    print("Lab accounts: admin/admin123, writer/write123, reader/read123, auditor/audit123")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        while True:
            conn, addr = server.accept()
            threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
