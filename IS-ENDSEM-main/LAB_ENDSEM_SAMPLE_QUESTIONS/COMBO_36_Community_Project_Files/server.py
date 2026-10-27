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

# Community Project Files: Labs 1, 2, 3, 5, 6, 7, 8. Lab 4 excluded.
# Standalone teaching example. See PRACTICE.txt for scope and limitations.
HOST, PORT = "127.0.0.1", 5136
BLOCK_CIPHER, KEY_BYTES = AES, 16
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "writer": {"password": "write123", "role": "writer"},
    "reader": {"password": "read123", "role": "reader"},
    "auditor": {"password": "audit123", "role": "auditor"},
}
REPORTS = {}
AUDIT_FILE = Path(__file__).with_name("audit.log")
LOCK = threading.RLock()

# Tiny textbook DH group for hand calculations, NOT secure.
P, G = 467, 2
PRIVATE_X = secrets.randbelow(P - 3) + 2
PUBLIC_Y = pow(G, PRIVATE_X, P)

def wrap_key(key):
    ephemeral = secrets.randbelow(P - 3) + 2
    public = pow(G, ephemeral, P)
    shared = pow(PUBLIC_Y, ephemeral, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return [public, b64(cipher.nonce), b64(ciphertext), b64(tag)]

def unwrap_key(wrapped):
    public, nonce, ciphertext, tag = wrapped
    shared = pow(public, PRIVATE_X, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=unb64(nonce))
    return cipher.decrypt_and_verify(unb64(ciphertext), unb64(tag))

# A fixed 160-bit prime-order subgroup: small enough for quick lab startup.
# Parameters are generated once by the builder; this is an educational signature.
SIG_P, SIG_Q, SIG_G = (174603574791232246354051371231605080226102972426590404703484661759244705455687110144281032625687997348483286138744890049654307711880324095118542939269921608487240410973422511846587762698868714850355890367869802591444302651887017839068243795781065968467603192888664962425797716555608719325248493301139873058093, 1415788254246462573557326432318736449382436643643, 66532922375832765569458357633272330911524606757062802983006867719777963116922806290453422052521474726084041409076712888494723042566045983280507959282043750412503955630760900213914798970454838153641377939685649844204321345401500704230511993352319887249032829379614149535962443650838420750542008343644888130928)
USER_SIGNING_KEYS = {u: secrets.randbelow(SIG_Q - 1) + 1 for u in USERS}
USER_VERIFY_KEYS = {u: pow(SIG_G, x, SIG_P) for u, x in USER_SIGNING_KEYS.items()}

def challenge(content, commitment):
    message = json.dumps([content, commitment], ensure_ascii=False).encode()
    return int.from_bytes(hashlib.sha256(message).digest(), "big") % SIG_Q

def sign_content(username, content):
    k = secrets.randbelow(SIG_Q - 1) + 1
    r = pow(SIG_G, k, SIG_P)
    e = challenge(content, r)
    return [e, (k + USER_SIGNING_KEYS[username] * e) % SIG_Q]

def verify_signature(username, content, signature):
    e, s = signature
    if not (0 <= e < SIG_Q and 0 <= s < SIG_Q):
        return False
    y = USER_VERIFY_KEYS[username]
    r = pow(SIG_G, s, SIG_P) * pow(pow(y, e, SIG_P), -1, SIG_P) % SIG_P
    return e == challenge(content, r)

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
    value = 5381
    for byte in text.encode():
        value = ((value * 33) + byte) & 0xffffffff
    return f"{value:08x}"

def affine_encrypt(plaintext, a, b):
    result = []
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((a * (ord(ch) - base) + b) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def affine_decrypt(ciphertext, a, b):
    a_inv = pow(a, -1, 26)
    result = []
    for ch in ciphertext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(a_inv * (ord(ch) - base - b) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = affine_encrypt(text, 15, 20)
    decrypted = affine_decrypt(encrypted, 15, 20)
    return {"algorithm": "Affine", "ciphertext": encrypted, "decrypted_text": decrypted}

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
