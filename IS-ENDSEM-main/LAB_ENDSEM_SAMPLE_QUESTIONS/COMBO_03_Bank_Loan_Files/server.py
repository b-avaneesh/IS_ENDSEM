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

# Bank Loan Files: Labs 1, 2, 3, 5, 6, 7, 8. Lab 4 excluded.
# Standalone teaching example. See PRACTICE.txt for scope and limitations.
HOST, PORT = "127.0.0.1", 5103
BLOCK_CIPHER, KEY_BYTES = AES, 32
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "writer": {"password": "write123", "role": "writer"},
    "reader": {"password": "read123", "role": "reader"},
    "auditor": {"password": "audit123", "role": "auditor"},
}
REPORTS = {}
AUDIT_FILE = Path(__file__).with_name("audit.log")
LOCK = threading.RLock()

SERVER_ECC = ECC.generate(curve="P-256")

def wrap_key(key):
    # ECC hybrid encryption: ephemeral ECDH -> SHA256 -> AES key wrapping.
    ephemeral = ECC.generate(curve="P-256")
    point = SERVER_ECC.pointQ * ephemeral.d
    shared_key = hashlib.sha256(int(point.x).to_bytes(32, "big")).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return [ephemeral.public_key().export_key(format="PEM"),
            b64(cipher.nonce), b64(ciphertext), b64(tag)]

def unwrap_key(wrapped):
    public_pem, nonce, ciphertext, tag = wrapped
    point = ECC.import_key(public_pem).pointQ * SERVER_ECC.d
    shared_key = hashlib.sha256(int(point.x).to_bytes(32, "big")).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=unb64(nonce))
    return cipher.decrypt_and_verify(unb64(ciphertext), unb64(tag))

USER_SIGNING_KEYS = {username: RSA.generate(2048) for username in USERS}

def sign_content(username, content):
    return b64(pkcs1_15.new(USER_SIGNING_KEYS[username]).sign(SHA256.new(content.encode())))

def verify_signature(username, content, signature):
    try:
        pkcs1_15.new(USER_SIGNING_KEYS[username].publickey()).verify(
            SHA256.new(content.encode()), unb64(signature))
        return True
    except (ValueError, TypeError):
        return False

HOM_P, HOM_G = 467, 2  # Tiny textbook group, not secure.
HOM_X = secrets.randbelow(HOM_P - 3) + 2
HOM_Y = pow(HOM_G, HOM_X, HOM_P)

def hom_encrypt(value):
    k = secrets.randbelow(HOM_P - 3) + 2
    return pow(HOM_G, k, HOM_P), value * pow(HOM_Y, k, HOM_P) % HOM_P

def homomorphic_demo(a, b):
    if not (1 <= a < HOM_P and 1 <= b < HOM_P):
        raise ValueError("Use integers from 1 to 466")
    ca, cb = hom_encrypt(a), hom_encrypt(b)
    combined = (ca[0] * cb[0] % HOM_P, ca[1] * cb[1] % HOM_P)
    result = combined[1] * pow(pow(combined[0], HOM_X, HOM_P), -1, HOM_P) % HOM_P
    return {"operation": "multiplication modulo 467", "encrypted_a": ca,
            "encrypted_b": cb, "encrypted_result": combined,
            "decrypted_result": result, "expected": a * b % HOM_P}

SEARCH_KEY = get_random_bytes(32)
INDEX_KEY = get_random_bytes(KEY_BYTES)
SEARCH_INDEX = {}

def search_token(word):
    return hmac.new(SEARCH_KEY, word.encode(), hashlib.sha256).hexdigest()

def add_to_index(report_id, content):
    for word in words(content):
        iv, encrypted_id = symmetric_encrypt(INDEX_KEY, report_id)
        SEARCH_INDEX.setdefault(search_token(word), []).append((iv, encrypted_id))

def search_reports(query):
    return sorted({symmetric_decrypt(INDEX_KEY, iv, encrypted_id)
                   for iv, encrypted_id in SEARCH_INDEX.get(search_token(query), [])})

def digest_text(text):
    return hashlib.md5(text.encode()).hexdigest()

def multiplicative_encrypt(plaintext, key):
    result = []
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base) * key % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def multiplicative_decrypt(ciphertext, key):
    key_inv = pow(key, -1, 26)
    result = []
    for ch in ciphertext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base) * key_inv % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = multiplicative_encrypt(text, 15)
    decrypted = multiplicative_decrypt(encrypted, 15)
    return {"algorithm": "Multiplicative", "ciphertext": encrypted, "decrypted_text": decrypted}

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
