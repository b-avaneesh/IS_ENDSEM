import base64
import hashlib
import hmac
import json
import os
import socket
import threading
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST, PORT = "127.0.0.1", 5000

# Lab-only accounts. In a real system, store salted password hashes instead.
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "doctor": {"password": "doc123", "role": "doctor"},
    "reception": {"password": "rec123", "role": "receptionist"},
    "auditor": {"password": "audit123", "role": "auditor"},
}

# Demo key pairs are generated at server startup. Real applications need secure key storage.
SERVER_RSA = RSA.generate(2048)
SERVER_PUBLIC = SERVER_RSA.publickey()
USER_SIGNING_KEYS = {username: RSA.generate(2048) for username in USERS}
SEARCH_KEY = get_random_bytes(32)  # HMAC search-token key
INDEX_AES_KEY = get_random_bytes(16)  # encrypts report IDs in the index
REPORTS = {}
SEARCH_INDEX = {}
AUDIT_FILE = "audit.log"
LOCK = threading.Lock()


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(data):
    return base64.b64decode(data.encode("ascii"))


def send_json(stream, obj):
    stream.write((json.dumps(obj) + "\n").encode("utf-8"))
    stream.flush()


def recv_json(stream):
    line = stream.readline()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def aes_encrypt(key, text):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return iv, ciphertext


def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")


def search_token(word):
    return hmac.new(SEARCH_KEY, word.lower().encode("utf-8"), hashlib.sha256).hexdigest()


def add_to_index(report_id, content):
    # Basic word matching: punctuation is stripped; no stemming or phrase search.
    words = {"".join(ch for ch in w.lower() if ch.isalnum()) for w in content.split()}
    for word in words:
        if not word:
            continue
        token = search_token(word)
        iv, enc_id = aes_encrypt(INDEX_AES_KEY, report_id)
        SEARCH_INDEX.setdefault(token, []).append((iv, enc_id))


def audit(username, role, action, result, detail=""):
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "username": username,
        "role": role,
        "action": action,
        "result": result,
        "detail": detail,
    }
    with LOCK:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def has_permission(role, action):
    permissions = {
        "admin": {"upload", "get", "search", "audit", "list", "vigenere", "paillier_add"},
        "doctor": {"upload", "get", "search", "list", "vigenere", "paillier_add"},
        "receptionist": {"search", "list"},  # can search IDs, not read full reports
        "auditor": {"audit", "list", "verify"},
    }
    return action in permissions.get(role, set())


def verify_report(report_id):
    item = REPORTS.get(report_id)
    if not item:
        return False, "Report not found"
    key = PKCS1_OAEP.new(SERVER_RSA).decrypt(unb64(item["wrapped_key"]))
    content = aes_decrypt(key, unb64(item["iv"]), unb64(item["ciphertext"]))
    digest_ok = hashlib.sha256(content.encode("utf-8")).hexdigest() == item["sha256"]
    try:
        pkcs1_15.new(USER_SIGNING_KEYS[item["author"]].publickey()).verify(
            SHA256.new(content.encode("utf-8")), unb64(item["signature"])
        )
        signature_ok = True
    except (ValueError, TypeError):
        signature_ok = False
    return digest_ok and signature_ok, "integrity and signature valid" if digest_ok and signature_ok else "verification failed"


def handle_request(username, role, req):
    action = req.get("action", "")
    if not has_permission(role, action):
        audit(username, role, action, "DENIED", "permission denied")
        return {"status": "error", "message": "Permission denied for this role"}

    try:
        if action == "upload":
            report_id = str(req.get("report_id", "")).strip()
            content = str(req.get("content", ""))
            if not report_id or not content:
                return {"status": "error", "message": "report_id and content are required"}
            if report_id in REPORTS:
                return {"status": "error", "message": "Report ID already exists"}

            aes_key = get_random_bytes(16)
            iv, ciphertext = aes_encrypt(aes_key, content)
            wrapped_key = PKCS1_OAEP.new(SERVER_PUBLIC).encrypt(aes_key)
            signature = pkcs1_15.new(USER_SIGNING_KEYS[username]).sign(
                SHA256.new(content.encode("utf-8"))
            )
            REPORTS[report_id] = {
                "iv": b64(iv),
                "ciphertext": b64(ciphertext),
                "wrapped_key": b64(wrapped_key),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "signature": b64(signature),
                "author": username,
            }
            add_to_index(report_id, content)
            audit(username, role, action, "SUCCESS", report_id)
            return {"status": "ok", "message": "Report encrypted, signed and stored", "report_id": report_id}

        if action == "get":
            report_id = str(req.get("report_id", ""))
            item = REPORTS.get(report_id)
            if not item:
                return {"status": "error", "message": "Report not found"}
            key = PKCS1_OAEP.new(SERVER_RSA).decrypt(unb64(item["wrapped_key"]))
            content = aes_decrypt(key, unb64(item["iv"]), unb64(item["ciphertext"]))
            digest_ok = hashlib.sha256(content.encode("utf-8")).hexdigest() == item["sha256"]
            try:
                pkcs1_15.new(USER_SIGNING_KEYS[item["author"]].publickey()).verify(
                    SHA256.new(content.encode("utf-8")), unb64(item["signature"])
                )
                sig_ok = True
            except (ValueError, TypeError):
                sig_ok = False
            audit(username, role, action, "SUCCESS" if digest_ok and sig_ok else "VERIFY_FAILED", report_id)
            if not (digest_ok and sig_ok):
                return {"status": "error", "message": "Integrity/signature verification failed"}
            return {"status": "ok", "report_id": report_id, "content": content,
                    "sha256": item["sha256"], "signature_verified": sig_ok}

        if action == "search":
            query = str(req.get("query", "")).strip().lower()
            if not query:
                return {"status": "error", "message": "Search query is required"}
            token = search_token(query)
            found = []
            seen = set()
            for iv, encrypted_id in SEARCH_INDEX.get(token, []):
                report_id = aes_decrypt(INDEX_AES_KEY, iv, encrypted_id)
                if report_id not in seen:
                    seen.add(report_id)
                    found.append(report_id)
            audit(username, role, action, "SUCCESS", query)
            # Receptionists receive IDs only; they cannot retrieve report contents.
            return {"status": "ok", "report_ids": found}

        if action == "list":
            return {"status": "ok", "report_ids": sorted(REPORTS.keys())}

        if action == "audit":
            if not os.path.exists(AUDIT_FILE):
                return {"status": "ok", "logs": []}
            with open(AUDIT_FILE, "r", encoding="utf-8") as f:
                logs = [json.loads(line) for line in f if line.strip()]
            return {"status": "ok", "logs": logs[-100:]}

        if action == "verify":
            report_id = str(req.get("report_id", ""))
            ok, message = verify_report(report_id)
            audit(username, role, action, "SUCCESS" if ok else "FAILED", report_id)
            return {"status": "ok", "verified": ok, "message": message}

        if action == "vigenere":
            text = str(req.get("text", ""))
            key = "".join(c for c in str(req.get("key", "")) if c.isalpha()).upper()
            if not key:
                return {"status": "error", "message": "Alphabetic key required"}
            out, j = [], 0
            for ch in text:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    shift = ord(key[j % len(key)]) - ord('A')
                    out.append(chr((ord(ch) - base + shift) % 26 + base))
                    j += 1
                else:
                    out.append(ch)
            audit(username, role, action, "SUCCESS", "Vigenere encryption")
            return {"status": "ok", "ciphertext": "".join(out)}

        if action == "paillier_add":
            # Optional dependency: pip install phe
            from phe import paillier
            a, b = int(req.get("a", 0)), int(req.get("b", 0))
            pub, priv = paillier.generate_paillier_keypair()
            encrypted_sum = pub.encrypt(a) + pub.encrypt(b)
            result = priv.decrypt(encrypted_sum)
            audit(username, role, action, "SUCCESS", f"{a}+{b}")
            return {"status": "ok", "decrypted_sum": result}

        return {"status": "error", "message": "Unknown action"}
    except Exception as exc:
        audit(username, role, action, "ERROR", type(exc).__name__)
        return {"status": "error", "message": "Request failed: " + type(exc).__name__}


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
    except (ConnectionError, json.JSONDecodeError, OSError):
        pass
    finally:
        print(f"Connection closed: {addr} ({username}/{role})")


def main():
    print(f"Server listening on {HOST}:{PORT}")
    print("Lab accounts: admin/admin123, doctor/doc123, reception/rec123, auditor/audit123")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        while True:
            conn, addr = server.accept()
            threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
