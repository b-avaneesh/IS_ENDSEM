"""Generate socket-based client/server cryptography lab solutions.
Run: python generator_server_client.py

The generated folder contains server.py, client.py and common.py (shared crypto).
The CLIENT hashes, signs, encrypts the record with a session key, protects that
key with the server's public key and homomorphically encrypts numeric values.
The SERVER unwraps the key, decrypts, compares hashes, verifies the signature,
timestamps the record with its timestamp authority, checks the submission
period, indexes it for search, tallies the homomorphic values without
decrypting them and decrypts only the final aggregate (optionally 2-of-2
threshold). Records persist in server_data/ across restarts.

Covers every algorithm in LAB_ENDSEM_SAMPLE_QUESTIONS (36 combos) plus the
client/server e-voting question.
"""
from pathlib import Path
import ast
import hashlib
import json
import os
import re

ACTIONS = {
    "submit": "Submit record (client hashes, signs, encrypts; server verifies, timestamps, indexes)",
    "verify": "Verify a stored record (hash, signature, timestamp, tamper check; no plaintext)",
    "view": "View a record (verify, then decrypt and show plaintext)",
    "list": "List record IDs",
    "search": "Search the encrypted index (field value / word / time range)",
    "tally": "Homomorphic tally of selected or all records (no individual decryption)",
    "decrypt": "Decrypt only the final aggregate (two authority passwords if threshold)",
    "audit": "View audit log",
    "classical": "Classical cipher demo",
    "he_demo": "Homomorphic demo on two integers",
    "tamper": "Tamper demo (corrupt a stored record, then verify it)",
}

ALGORITHM_CHOICES = {
    "cipher": ["AES-256", "AES-128", "AES-192", "DES", "Triple-DES"],
    "mode": ["CBC", "ECB", "CFB", "OFB", "CTR"],
    "hash": ["SHA-512", "SHA-256", "SHA-1", "MD5", "SHA3-256", "CUSTOM32"],
    "wrap": ["RSA", "ECDH", "DH", "ElGamal"],
    "signature": ["ElGamal", "RSA", "RSA-PSS", "Schnorr"],
    "search": ["SSE", "RSA_owner_scan", "Paillier_owner_scan"],
    "sse_cipher": ["HMAC-SHA256", "AES", "DES"],
    "homomorphic": ["Paillier", "RSA", "ElGamal", "ElGamal-Exp"],
    "classical": ["none", "Additive", "Multiplicative", "Affine", "Vigenere", "Autokey", "Playfair", "Hill", "Transposition"],
}

CATEGORY_LABELS = {
    "cipher": "Symmetric cipher (Lab 2)", "mode": "Block cipher mode", "hash": "Hash (Lab 5)",
    "wrap": "Session-key protection (Lab 3)", "signature": "Digital signature (Lab 6)",
    "search": "Searchable encryption (Lab 8)", "sse_cipher": "SSE token cipher",
    "homomorphic": "Homomorphic scheme (Lab 7)", "classical": "Classical cipher demo (Lab 1)",
}

CLASSICAL_DEFAULT_KEYS = {
    # Same keys as the Lab 1 manual exercises and the LAB_ENDSEM_SAMPLE_QUESTIONS combos.
    "Additive": "20", "Multiplicative": "15", "Affine": "15,20", "Vigenere": "HEALTH", "Autokey": "H",
    "Playfair": "GUIDANCE", "Hill": "3 3 2 7", "Transposition": "ZEBRA",
}

RSA_KEY_SIZES = (1024, 2048, 3072, 4096)
RSA_DEFAULT_BITS = {"wrap": 2048, "signature": 2048, "homomorphic": 2048}


# =====================================================================
# common.py - shared by client and server
# =====================================================================
COMMON = r'''"""Shared configuration and cryptography. server.py and client.py import this file.
Keep common.py, server.py and client.py in the same folder."""
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from math import gcd, isqrt, lcm

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Util.Padding import pad, unpad

CONFIG = __CONFIG__
ALG = CONFIG["algorithms"]
METRICS = CONFIG["metrics"]
IST = timezone(timedelta(hours=5, minutes=30))
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_VALUE = 10**12
EXP_ELGAMAL_BOUND = 10**10


# ---------------- general helpers ----------------
def now():
    return datetime.now(IST).strftime(TIME_FORMAT)


def send_json(stream, obj):
    stream.write((json.dumps(obj) + "\n").encode())
    stream.flush()


def recv_json(stream):
    line = stream.readline()
    return json.loads(line.decode()) if line else None


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def show(title, details):
    print("\n=== " + title + " ===")
    for name, value in details.items():
        print(f"{name}: {value}")


def check_id(record_id):
    record_id = str(record_id).strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", record_id):
        raise ValueError("Record ID must be 1-40 letters, digits, _ or -.")
    return record_id


def normalize_record(values):
    if not isinstance(values, dict) or set(values) != {f["name"] for f in CONFIG["fields"]}:
        raise ValueError("Record fields do not match the configured schema.")
    record = {}
    for field in CONFIG["fields"]:
        name, value = field["name"], str(values[field["name"]]).strip()
        if not value:
            raise ValueError(name + " cannot be empty.")
        if field["type"] == "text":
            if len(value) > 4000:
                raise ValueError(name + " is too long.")
            record[name] = value
        elif field["type"] == "choice":
            matches = [c for c in field["choices"] if c.casefold() == value.casefold()]
            if not matches:
                raise ValueError(name + ": choose one of " + ", ".join(field["choices"]))
            record[name] = matches[0]
        else:
            if not re.fullmatch(r"[0-9]{1,13}", value) or int(value) > MAX_VALUE:
                raise ValueError(f"{name}: invalid value, enter a whole number from 0 to {MAX_VALUE}.")
            record[name] = int(value)
    return record


def record_text(record_id, record):
    # Canonical text that is hashed and signed: binds the ID to every field.
    return canonical({"id": record_id, "fields": record})


# ---------------- Lab 5: hashing ----------------
def custom32(data):
    value = 5381
    for byte in data:
        value = ((value * 33) + byte) & 0xFFFFFFFF
    return f"{value:08x}"


def digest_text(text):
    data = text.encode()
    if ALG["hash"] == "CUSTOM32":
        return custom32(data)
    return {"SHA-512": hashlib.sha512, "SHA-256": hashlib.sha256, "SHA-1": hashlib.sha1,
            "MD5": hashlib.md5, "SHA3-256": hashlib.sha3_256}[ALG["hash"]](data).hexdigest()


def field_digest(record):
    if not CONFIG["hash_field"]:
        return None
    return digest_text(str(record[CONFIG["hash_field"]]))


# ---------------- Lab 2: symmetric encryption ----------------
CIPHERS = {"AES-128": (AES, 16), "AES-192": (AES, 24), "AES-256": (AES, 32), "DES": (DES, 8), "Triple-DES": (DES3, 24)}


def session_key():
    family, size = CIPHERS[ALG["cipher"]]
    while True:
        key = os.urandom(size)
        if family is not DES3:
            return key
        try:
            return DES3.adjust_key_parity(key)
        except ValueError:
            continue


def sym_encrypt(key, text):
    family, _ = CIPHERS[ALG["cipher"]]
    mode, data = ALG["mode"], text.encode()
    if mode == "ECB":
        return {"iv": "", "ciphertext": family.new(key, family.MODE_ECB).encrypt(pad(data, family.block_size)).hex()}
    if mode == "CTR":
        cipher = family.new(key, family.MODE_CTR)
        return {"iv": cipher.nonce.hex(), "ciphertext": cipher.encrypt(data).hex()}
    cipher = family.new(key, getattr(family, "MODE_" + mode))
    body = pad(data, family.block_size) if mode == "CBC" else data
    return {"iv": cipher.iv.hex(), "ciphertext": cipher.encrypt(body).hex()}


def sym_decrypt(key, packet):
    family, _ = CIPHERS[ALG["cipher"]]
    mode, data = ALG["mode"], bytes.fromhex(packet["ciphertext"])
    if mode == "ECB":
        return unpad(family.new(key, family.MODE_ECB).decrypt(data), family.block_size).decode()
    if mode == "CTR":
        return family.new(key, family.MODE_CTR, nonce=bytes.fromhex(packet["iv"])).decrypt(data).decode()
    plain = family.new(key, getattr(family, "MODE_" + mode), iv=bytes.fromhex(packet["iv"])).decrypt(data)
    return (unpad(plain, family.block_size) if mode == "CBC" else plain).decode()


# ---------------- Lab 3: protecting the session key ----------------
def kdf(secret_bytes):
    return hashlib.sha256(secret_bytes).digest()


def int_bytes(value):
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def eax_seal(key32, data):
    cipher = AES.new(key32, AES.MODE_EAX)
    sealed, tag = cipher.encrypt_and_digest(data)
    return {"nonce": cipher.nonce.hex(), "tag": tag.hex(), "sealed": sealed.hex()}


def eax_open(key32, box):
    cipher = AES.new(key32, AES.MODE_EAX, nonce=bytes.fromhex(box["nonce"]))
    return cipher.decrypt_and_verify(bytes.fromhex(box["sealed"]), bytes.fromhex(box["tag"]))


def wrap_keygen(group):
    kind = ALG["wrap"]
    if kind == "RSA":
        key = RSA.generate(ALG["rsa_bits"]["wrap"])
        return {"pem": key.export_key().decode()}, {"pem": key.publickey().export_key().decode()}
    if kind == "ECDH":
        key = ECC.generate(curve="P-256")
        return {"pem": key.export_key(format="PEM")}, {"pem": key.public_key().export_key(format="PEM")}
    x = secrets.randbelow(group["q"] - 1) + 1
    return {"x": x}, {"y": pow(group["g"], x, group["p"])}


def wrap_key(key, public, group):
    kind = ALG["wrap"]
    if kind == "RSA":
        cipher = PKCS1_OAEP.new(RSA.import_key(public["pem"]), hashAlgo=SHA256)
        return {"scheme": "RSA-OAEP", "wrapped": cipher.encrypt(key).hex()}
    if kind == "ECDH":
        ephemeral = ECC.generate(curve="P-256")
        secret = key_agreement(eph_priv=ephemeral, static_pub=ECC.import_key(public["pem"]), kdf=kdf)
        return {"scheme": "ECDH P-256 + AES-EAX", "ephemeral": ephemeral.public_key().export_key(format="PEM"),
                **eax_seal(secret, key)}
    p, q, g, y = group["p"], group["q"], group["g"], public["y"]
    k = secrets.randbelow(q - 1) + 1
    if kind == "DH":
        # Client sends A = g^a; both sides derive the shared secret y^a = A^x.
        return {"scheme": "DH + AES-EAX", "A": pow(g, k, p), **eax_seal(kdf(int_bytes(pow(y, k, p))), key)}
    # ElGamal encryption of the key itself; the leading 0x01 byte keeps leading zero bytes.
    m = int.from_bytes(b"\x01" + key, "big")
    return {"scheme": "ElGamal", "c1": pow(g, k, p), "c2": m * pow(y, k, p) % p}


def unwrap_key(wrapped, private, group):
    kind = ALG["wrap"]
    if kind == "RSA":
        return PKCS1_OAEP.new(RSA.import_key(private["pem"]), hashAlgo=SHA256).decrypt(bytes.fromhex(wrapped["wrapped"]))
    if kind == "ECDH":
        secret = key_agreement(static_priv=ECC.import_key(private["pem"]), eph_pub=ECC.import_key(wrapped["ephemeral"]), kdf=kdf)
        return eax_open(secret, wrapped)
    p, x = group["p"], private["x"]
    if kind == "DH":
        return eax_open(kdf(int_bytes(pow(wrapped["A"], x, p))), wrapped)
    m = wrapped["c2"] * pow(pow(wrapped["c1"], x, p), -1, p) % p
    return int_bytes(m)[1:]


# ---------------- Lab 6: digital signatures ----------------
def signing_keygen(group):
    if ALG["signature"] in ("RSA", "RSA-PSS"):
        key = RSA.generate(ALG["rsa_bits"]["signature"])
        return {"pem": key.export_key().decode()}, {"pem": key.publickey().export_key().decode()}
    x = secrets.randbelow(group["q"] - 1) + 1
    return {"x": x}, {"y": pow(group["g"], x, group["p"])}


def schnorr_challenge(r, digest, q):
    return int.from_bytes(hashlib.sha256(f"{r}|{digest}".encode()).digest(), "big") % q


def sign_digest(digest, private, group):
    kind = ALG["signature"]
    if kind in ("RSA", "RSA-PSS"):
        scheme = pkcs1_15 if kind == "RSA" else pss
        return scheme.new(RSA.import_key(private["pem"])).sign(SHA256.new(digest.encode())).hex()
    p, q, g, x = group["p"], group["q"], group["g"], private["x"]
    if kind == "ElGamal":
        h = int(digest, 16) % (p - 1)
        while True:
            k = secrets.randbelow(p - 2) + 1
            if gcd(k, p - 1) == 1:
                break
        r = pow(g, k, p)
        return [r, (h - x * r) * pow(k, -1, p - 1) % (p - 1)]
    k = secrets.randbelow(q - 1) + 1
    e = schnorr_challenge(pow(g, k, p), digest, q)
    return [e, (k + x * e) % q]


def verify_digest(digest, signature, public, group):
    """Return (valid, details) so both sides can print the comparison."""
    kind = ALG["signature"]
    if kind in ("RSA", "RSA-PSS"):
        scheme = pkcs1_15 if kind == "RSA" else pss
        try:
            scheme.new(RSA.import_key(public["pem"])).verify(SHA256.new(digest.encode()), bytes.fromhex(signature))
            return True, {"Signature check": kind + " over SHA-256(digest): valid"}
        except (ValueError, TypeError):
            return False, {"Signature check": kind + " over SHA-256(digest): INVALID"}
    p, q, g, y = group["p"], group["q"], group["g"], public["y"]
    if kind == "ElGamal":
        r, s = signature
        if not (0 < r < p and 0 <= s < p - 1):
            return False, {"Signature check": "ElGamal values out of range"}
        left, right = pow(g, int(digest, 16) % (p - 1), p), pow(y, r, p) * pow(r, s, p) % p
        return left == right, {"g^H mod p": hex(left), "y^r * r^s mod p": hex(right)}
    e, s = signature
    if not (0 <= e < q and 0 <= s < q):
        return False, {"Signature check": "Schnorr values out of range"}
    r = pow(g, s, p) * pow(pow(y, e, p), -1, p) % p
    recomputed = schnorr_challenge(r, digest, q)
    return recomputed == e, {"Schnorr e": hex(e), "Recomputed e": hex(recomputed)}


# ---------------- Lab 7: homomorphic encryption ----------------
def he_keygen(group):
    """Return (public, secret exponent d, period). Decryption raises the ciphertext to d."""
    scheme = ALG["homomorphic"]
    if scheme == "Paillier":
        from Crypto.Util.number import getPrime
        while True:
            p, q = getPrime(1024), getPrime(1024)
            n, lam = p * q, lcm(p - 1, q - 1)
            if p != q and gcd(lam, n) == 1:
                break
        # d is a multiple of lambda with d = 1 mod n, so L(c^d mod n^2) = m.
        return {"n": n, "g": n + 1}, lam * pow(lam, -1, n), n * lam
    if scheme == "RSA":
        key = RSA.generate(ALG["rsa_bits"]["homomorphic"])
        lam = lcm(key.p - 1, key.q - 1)
        return {"n": int(key.n), "e": int(key.e)}, int(key.d) % lam, lam
    x = secrets.randbelow(group["q"] - 1) + 1
    return {**group, "y": pow(group["g"], x, group["p"])}, x, group["q"]


def he_modulus(public):
    return public["p"] if ALG["homomorphic"].startswith("ElGamal") else public["n"]


def elgamal_plain(message, public):
    # Exponential ElGamal encodes m as g^m, so products of ciphertexts ADD the plaintexts.
    if ALG["homomorphic"] == "ElGamal-Exp":
        if not 0 <= message <= EXP_ELGAMAL_BOUND:
            raise ValueError("Value outside the exponential ElGamal range.")
        return pow(public["g"], message, public["p"])
    if not 0 < message < public["p"]:
        raise ValueError("Value outside the ElGamal range.")
    return message


def he_encrypt(message, public):
    scheme = ALG["homomorphic"]
    if scheme == "Paillier":
        n = public["n"]
        if not 0 <= message < n:
            raise ValueError("Value outside the Paillier range.")
        while True:
            r = secrets.randbelow(n - 1) + 1
            if gcd(r, n) == 1:
                break
        return pow(n + 1, message, n * n) * pow(r, n, n * n) % (n * n), r
    if scheme == "RSA":
        if not 0 < message < public["n"]:
            raise ValueError("Value outside the RSA range.")
        # Textbook RSA: E(a) * E(b) = E(a * b); deterministic, so no randomness.
        return pow(message, public["e"], public["n"]), None
    p = public["p"]
    k = secrets.randbelow(public["q"] - 1) + 1
    return [pow(public["g"], k, p), elgamal_plain(message, public) * pow(public["y"], k, p) % p], k


def he_matches(message, randomness, ciphertext, public):
    # Re-encrypt with the randomness hidden inside the encrypted payload; never decrypts.
    scheme = ALG["homomorphic"]
    if scheme == "Paillier":
        n = public["n"]
        if not isinstance(randomness, int) or not 0 < randomness < n or gcd(randomness, n) != 1:
            return False
        return ciphertext == pow(n + 1, message, n * n) * pow(randomness, n, n * n) % (n * n)
    if scheme == "RSA":
        return randomness is None and ciphertext == pow(message, public["e"], public["n"])
    p = public["p"]
    if not isinstance(randomness, int) or not 0 < randomness < public["q"]:
        return False
    return ciphertext == [pow(public["g"], randomness, p), elgamal_plain(message, public) * pow(public["y"], randomness, p) % p]


def he_identity():
    return [1, 1] if ALG["homomorphic"].startswith("ElGamal") else 1


def he_combine(first, second, public):
    scheme = ALG["homomorphic"]
    if scheme == "Paillier":
        return first * second % (public["n"] ** 2)
    if scheme == "RSA":
        return first * second % public["n"]
    p = public["p"]
    return [first[0] * second[0] % p, first[1] * second[1] % p]


def he_partial(ciphertext, exponent, public):
    scheme = ALG["homomorphic"]
    if scheme == "Paillier":
        return pow(ciphertext, exponent, public["n"] ** 2)
    if scheme == "RSA":
        return pow(ciphertext, exponent, public["n"])
    return pow(ciphertext[0], exponent, public["p"])


def discrete_log(target, public):
    # Baby-step giant-step for g^m = target, 0 <= m <= EXP_ELGAMAL_BOUND.
    p, g = public["p"], public["g"]
    step = isqrt(EXP_ELGAMAL_BOUND) + 1
    baby, value = {}, 1
    for j in range(step):
        baby.setdefault(value, j)
        value = value * g % p
    giant = pow(g, -step, p)
    for i in range(step + 1):
        if target in baby:
            return i * step + baby[target]
        target = target * giant % p
    raise ValueError("Aggregate exceeds the exponential ElGamal bound.")


def he_join(ciphertext, partials, public):
    scheme = ALG["homomorphic"]
    if scheme == "Paillier":
        n = public["n"]
        combined = 1
        for part in partials:
            combined = combined * part % (n * n)
        if (combined - 1) % n:
            raise ValueError("Invalid combined partial decryption.")
        return (combined - 1) // n % n
    if scheme == "RSA":
        result = 1
        for part in partials:
            result = result * part % public["n"]
        return result
    p, shared = public["p"], 1
    for part in partials:
        shared = shared * part % p
    plain = ciphertext[1] * pow(shared, -1, p) % p
    return discrete_log(plain, public) if scheme == "ElGamal-Exp" else plain


def he_hex(ciphertext):
    return [hex(part) for part in ciphertext] if isinstance(ciphertext, list) else hex(ciphertext)


def he_additive():
    return ALG["homomorphic"] in ("Paillier", "ElGamal-Exp")


def metric_values(record):
    values = {}
    for name, metric in METRICS.items():
        if metric["kind"] == "record_count":
            values[name] = 1
        elif metric["kind"] == "count":
            values[name] = int(record[metric["field"]] == metric["choice"])
        else:
            values[name] = int(record[metric["field"]])
    return values


def encode_metric(name, value):
    if ALG["homomorphic"] == "ElGamal-Exp" and value > EXP_ELGAMAL_BOUND:
        raise ValueError(METRICS[name]["label"] + f": exponential ElGamal supports values up to {EXP_ELGAMAL_BOUND}.")
    if he_additive():
        return value
    # Multiplicative schemes: E(2^a) * E(2^b) = E(2^(a+b)), so counts become exponents of 2.
    if METRICS[name]["kind"] in ("record_count", "count"):
        return 2 ** value
    if value < 1:
        raise ValueError(METRICS[name]["label"] + ": multiplicative homomorphism needs values of at least 1.")
    return value


def decode_metric(name, value):
    if he_additive() or METRICS[name]["kind"] not in ("record_count", "count"):
        return value
    if value < 1 or value & (value - 1):
        raise ValueError("Decrypted count is not a power of two.")
    return value.bit_length() - 1


def check_capacity(count, public):
    if ALG["homomorphic"] == "ElGamal-Exp":
        return
    if ALG["homomorphic"] == "Paillier":
        limit = count * MAX_VALUE
    elif any(m["kind"] == "product" for m in METRICS.values()):
        limit = MAX_VALUE ** count
    else:
        limit = 2 ** count
    if limit >= he_modulus(public):
        raise ValueError("Aggregate could overflow the plaintext range; select fewer records.")


# ---------------- Lab 8: searchable encryption ----------------
def words(text):
    return sorted(set(re.findall(r"[^\W_]+", str(text).casefold())))


def index_terms(record):
    terms = {}
    for field in CONFIG["fields"]:
        if field["search"] == "none":
            continue
        value = record[field["name"]]
        items = words(value) if field["search"] == "words" else [str(value).casefold()]
        terms[field["name"]] = [field["name"] + ":" + item for item in items]
    return terms


def query_term(field, query):
    if field["search"] == "words":
        items = words(query)
        if len(items) != 1:
            raise ValueError("Enter exactly one search word.")
        return field["name"] + ":" + items[0]
    value = str(query).strip()
    if field["type"] == "integer":
        value = str(int(value))
    return field["name"] + ":" + value.casefold()


def term_hash(term):
    return hashlib.sha256(term.encode()).hexdigest()


def sse_token(term, key):
    # Deterministic keyed token: equal keywords give equal tokens, so the server can match them.
    if ALG["sse_cipher"] == "HMAC-SHA256":
        return hmac.new(key, term.encode(), hashlib.sha256).hexdigest()
    digest = hashlib.sha256(term.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB) if ALG["sse_cipher"] == "AES" else DES.new(key[:8], DES.MODE_ECB)
    return cipher.encrypt(digest).hex()


def paillier_raw_encrypt(message, n):
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            break
    return pow(n + 1, message, n * n) * pow(r, n, n * n) % (n * n)


def paillier_raw_decrypt(ciphertext, private):
    n = private["n"]
    return (pow(ciphertext, private["lam"], n * n) - 1) // n * private["mu"] % n


# ---------------- Lab 1: classical ciphers ----------------
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def letters_only(text):
    return "".join(ch for ch in text.upper() if ch in LETTERS)


def map_letters(text, transform):
    out, position = [], 0
    for ch in text:
        if ch.isascii() and ch.upper() in LETTERS:
            letter = chr(transform(ord(ch.upper()) - 65, position) % 26 + 65)
            position += 1
            out.append(letter if ch.isupper() else letter.lower())
        else:
            out.append(ch)
    return "".join(out)


def parse_classical_key(kind, raw):
    raw = str(raw).strip()
    if kind in ("Additive", "Multiplicative"):
        k = int(raw)
        if kind == "Multiplicative" and gcd(k, 26) != 1:
            raise ValueError("Multiplicative key must be coprime with 26.")
        return k % 26
    if kind == "Affine":
        a, b = (int(x) for x in raw.replace(" ", "").split(","))
        if gcd(a, 26) != 1:
            raise ValueError("Affine 'a' must be coprime with 26.")
        return a, b
    if kind == "Hill":
        a, b, c, d = (int(x) for x in raw.replace(",", " ").split())
        if gcd((a * d - b * c) % 26, 26) != 1:
            raise ValueError("Hill matrix determinant must be coprime with 26.")
        return [[a, b], [c, d]]
    key = letters_only(raw)
    if not key:
        raise ValueError("Key must contain letters.")
    return key


def playfair_square(key):
    seen = []
    for ch in (key + LETTERS).replace("J", "I"):
        if ch in LETTERS and ch not in seen:
            seen.append(ch)
    return seen


def playfair(text, key, decrypt):
    square = playfair_square(key)
    letters = letters_only(text).replace("J", "I")
    if not decrypt:
        pairs, i = [], 0
        while i < len(letters):
            a = letters[i]
            b = letters[i + 1] if i + 1 < len(letters) else "X"
            if a == b:
                b = "X"
                i += 1
            else:
                i += 2
            pairs.append((a, b))
    else:
        pairs = [(letters[i], letters[i + 1]) for i in range(0, len(letters) - 1, 2)]
    shift = -1 if decrypt else 1
    out = []
    for a, b in pairs:
        ra, ca = divmod(square.index(a), 5)
        rb, cb = divmod(square.index(b), 5)
        if ra == rb:
            out += [square[ra * 5 + (ca + shift) % 5], square[rb * 5 + (cb + shift) % 5]]
        elif ca == cb:
            out += [square[((ra + shift) % 5) * 5 + ca], square[((rb + shift) % 5) * 5 + cb]]
        else:
            out += [square[ra * 5 + cb], square[rb * 5 + ca]]
    return "".join(out)


def hill(text, matrix, decrypt):
    letters = letters_only(text)
    if len(letters) % 2:
        letters += "X"
    (a, b), (c, d) = matrix
    if decrypt:
        inv = pow((a * d - b * c) % 26, -1, 26)
        a, b, c, d = d * inv, -b * inv, -c * inv, a * inv
    out = []
    for i in range(0, len(letters), 2):
        x, y = ord(letters[i]) - 65, ord(letters[i + 1]) - 65
        out += [chr((a * x + b * y) % 26 + 65), chr((c * x + d * y) % 26 + 65)]
    return "".join(out)


def transposition(text, key, decrypt):
    cols = len(key)
    order = sorted(range(cols), key=lambda i: (key[i], i))
    if not decrypt:
        body = text + "X" * (-len(text) % cols)
        rows = [body[i:i + cols] for i in range(0, len(body), cols)]
        return "".join("".join(row[c] for row in rows) for c in order)
    rows_count = len(text) // cols
    columns, pos = {}, 0
    for c in order:
        columns[c] = text[pos:pos + rows_count]
        pos += rows_count
    return "".join(columns[c][r] for r in range(rows_count) for c in range(cols))


def classical_apply(text, decrypt):
    kind = ALG["classical"]
    key = parse_classical_key(kind, ALG["classical_key"])
    sign = -1 if decrypt else 1
    if kind == "Additive":
        return map_letters(text, lambda x, i: x + sign * key)
    if kind == "Multiplicative":
        k = pow(key, -1, 26) if decrypt else key
        return map_letters(text, lambda x, i: x * k)
    if kind == "Affine":
        a, b = key
        if decrypt:
            inv = pow(a, -1, 26)
            return map_letters(text, lambda x, i: inv * (x - b))
        return map_letters(text, lambda x, i: a * x + b)
    if kind == "Vigenere":
        return map_letters(text, lambda x, i: x + sign * (ord(key[i % len(key)]) - 65))
    if kind == "Autokey":
        stream = [ord(ch) - 65 for ch in key]

        def step(x, i):
            k = stream[i]
            plain = (x - k) % 26 if decrypt else x
            stream.append(plain)
            return x + sign * k
        return map_letters(text, step)
    if kind == "Playfair":
        return playfair(text, key, decrypt)
    if kind == "Hill":
        return hill(text, key, decrypt)
    return transposition(text, key, decrypt)


def classical_demo(text):
    if not text or not all(ch.isascii() for ch in text) or not any(ch.isalpha() for ch in text):
        raise ValueError("Use English letters A-Z for the classical cipher demo.")
    ciphertext = classical_apply(text, False)
    return {"algorithm": ALG["classical"], "key": ALG["classical_key"], "plaintext": text,
            "ciphertext": ciphertext, "decrypted": classical_apply(ciphertext, True)}
'''


# =====================================================================
# server.py
# =====================================================================
SERVER = r'''"""SERVER - run this first:  python server.py
Unwraps session keys, decrypts, compares hashes, verifies signatures,
timestamps (trusted authority), indexes, tallies homomorphically and decrypts
only the final aggregate. Data persists in server_data/."""
import getpass
import hashlib
import hmac
import json
import os
import socket
import threading
from datetime import datetime
from pathlib import Path

from Crypto.PublicKey import DSA, RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from common import *

BASE = Path(__file__).resolve().parent / "server_data"
LOCK = threading.RLock()
DEMO_KEYS = {}


# ---------------- storage ----------------
def save(name, value):
    path = BASE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def load(name):
    return json.loads((BASE / name).read_text(encoding="utf-8"))


def exists(name):
    return (BASE / name).exists()


def audit(username, role, action, result, detail=""):
    BASE.mkdir(parents=True, exist_ok=True)
    entry = {"time": now(), "username": username, "role": role, "action": action, "result": result, "detail": detail}
    with LOCK, open(BASE / "audit.log", "a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")


# ---------------- password-protected authority shares ----------------
def password_key(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)


def protect(value, password):
    salt = os.urandom(16)
    cipher = AES.new(password_key(password, salt), AES.MODE_EAX)
    sealed, tag = cipher.encrypt_and_digest(str(value).encode())
    return {"salt": salt.hex(), "nonce": cipher.nonce.hex(), "tag": tag.hex(), "sealed": sealed.hex()}


def unprotect(box, password):
    cipher = AES.new(password_key(password, bytes.fromhex(box["salt"])), AES.MODE_EAX, nonce=bytes.fromhex(box["nonce"]))
    try:
        return int(cipher.decrypt_and_verify(bytes.fromhex(box["sealed"]), bytes.fromhex(box["tag"])).decode())
    except ValueError:
        raise ValueError("Wrong authority password.") from None


def new_password(label):
    while True:
        first = getpass.getpass(f"Set {label} password: ")
        if first and first == getpass.getpass("Confirm password: "):
            return first
        print("Passwords must be nonempty and match.")


# ---------------- first-run key generation ----------------
def setup():
    if exists("keys/setup_done.json"):
        return
    print("\nFIRST-RUN SERVER SETUP")
    if CONFIG["use_deadline"]:
        print("Enter the submission period in IST as YYYY-MM-DD HH:MM:SS.")
        while True:
            try:
                start = datetime.strptime(input("Submissions start: ").strip(), TIME_FORMAT)
                deadline = datetime.strptime(input("Submission deadline: ").strip(), TIME_FORMAT)
                if deadline > start:
                    break
                print("Deadline must be after the start.")
            except ValueError:
                print("Use the format YYYY-MM-DD HH:MM:SS.")
        settings = {"start": start.strftime(TIME_FORMAT), "deadline": deadline.strftime(TIME_FORMAT)}
    else:
        settings = {"start": "1970-01-01 00:00:00", "deadline": "9999-12-31 23:59:59"}
    passwords = [new_password("authority 1"), new_password("authority 2")] if CONFIG["threshold"] else None
    group = None
    if (ALG["wrap"] in ("DH", "ElGamal") or ALG["signature"] in ("ElGamal", "Schnorr")
            or ALG["homomorphic"].startswith("ElGamal")):
        print("Generating 2048-bit group (p, q, g)... (takes a few seconds)")
        params = DSA.generate(2048)
        group = {"p": int(params.p), "q": int(params.q), "g": int(params.g)}
    save("keys/group.json", group)
    print("Generating " + ALG["wrap"] + " session-key protection keys...")
    private, public = wrap_keygen(group)
    save("keys/wrap_private.json", private)
    save("keys/wrap_public.json", public)
    print("Generating timestamp authority (RSA-2048) key...")
    tsa = RSA.generate(2048)
    save("keys/tsa_private.json", tsa.export_key().decode())
    save("keys/tsa_public.json", tsa.publickey().export_key().decode())
    print("Generating " + ALG["search"] + " search keys...")
    if ALG["search"] == "SSE":
        save("keys/search.json", {"key": os.urandom(32).hex()})
    elif ALG["search"] == "RSA_owner_scan":
        key = RSA.generate(2048)
        save("keys/search.json", {"pem": key.export_key().decode(), "public": key.publickey().export_key().decode()})
    else:
        from Crypto.Util.number import getPrime
        while True:
            p, q = getPrime(1024), getPrime(1024)
            if p != q and gcd(p * q, (p - 1) * (q - 1)) == 1:
                break
        n, lam = p * q, lcm(p - 1, q - 1)
        save("keys/search.json", {"n": n, "lam": lam, "mu": pow(lam, -1, n)})
    print("Generating " + ALG["homomorphic"] + " homomorphic keys...")
    he_public, secret, period = he_keygen(group)
    save("keys/he_public.json", he_public)
    if CONFIG["threshold"]:
        # 2-of-2 additive split of the decryption exponent; the full exponent is never stored.
        share1 = secrets.randbelow(period - 1) + 1
        save("keys/authority_1.json", protect(share1, passwords[0]))
        save("keys/authority_2.json", protect((secret - share1) % period, passwords[1]))
    else:
        save("keys/he_private.json", {"d": secret})
    save("keys/settings.json", settings)
    save("keys/setup_done.json", {"created_at": now()})
    print("Setup complete.")


def bundle():
    return {"group": load("keys/group.json"), "wrap": load("keys/wrap_public.json"),
            "he": load("keys/he_public.json"), "tsa": load("keys/tsa_public.json")}


# ---------------- timestamp authority ----------------
def tsa_message(record_id, digest, timestamp):
    return SHA256.new(canonical({"id": record_id, "digest": digest, "timestamp": timestamp}).encode())


def tsa_sign(record_id, digest, timestamp):
    return pkcs1_15.new(RSA.import_key(load("keys/tsa_private.json"))).sign(tsa_message(record_id, digest, timestamp)).hex()


def tsa_valid(record_id, digest, timestamp, signature):
    try:
        pkcs1_15.new(RSA.import_key(load("keys/tsa_public.json"))).verify(tsa_message(record_id, digest, timestamp), bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


def in_period(timestamp):
    settings = load("keys/settings.json")
    return settings["start"] <= timestamp <= settings["deadline"]


# ---------------- search index ----------------
def build_index(record):
    keys = load("keys/search.json")
    index = {}
    for field, terms in index_terms(record).items():
        if ALG["search"] == "SSE":
            index[field] = [sse_token(t, bytes.fromhex(keys["key"])) for t in terms]
        elif ALG["search"] == "RSA_owner_scan":
            cipher = PKCS1_OAEP.new(RSA.import_key(keys["public"]), hashAlgo=SHA256)
            index[field] = [cipher.encrypt(bytes.fromhex(term_hash(t))).hex() for t in terms]
        else:
            index[field] = [paillier_raw_encrypt(int(term_hash(t), 16), keys["n"]) for t in terms]
    return index


def plain_index(index):
    # Owner-side view of the index, used to check it was not altered.
    keys = load("keys/search.json")
    if ALG["search"] == "SSE":
        return {f: sorted(v) for f, v in index.items()}
    if ALG["search"] == "RSA_owner_scan":
        cipher = PKCS1_OAEP.new(RSA.import_key(keys["pem"]), hashAlgo=SHA256)
        return {f: sorted(cipher.decrypt(bytes.fromhex(e)).hex() for e in v) for f, v in index.items()}
    return {f: sorted(format(paillier_raw_decrypt(e, keys), "064x") for e in v) for f, v in index.items()}


def expected_plain_index(record):
    keys = load("keys/search.json")
    if ALG["search"] == "SSE":
        return {f: sorted(sse_token(t, bytes.fromhex(keys["key"])) for t in terms) for f, terms in index_terms(record).items()}
    return {f: sorted(term_hash(t) for t in terms) for f, terms in index_terms(record).items()}


def index_match(entries, term):
    keys = load("keys/search.json")
    if ALG["search"] == "SSE":
        return sse_token(term, bytes.fromhex(keys["key"])) in entries
    if ALG["search"] == "RSA_owner_scan":
        # Owner scan: decrypt each OAEP token with the private key and compare.
        cipher = PKCS1_OAEP.new(RSA.import_key(keys["pem"]), hashAlgo=SHA256)
        return any(hmac.compare_digest(cipher.decrypt(bytes.fromhex(e)).hex(), term_hash(term)) for e in entries)
    # Paillier scan: E(h_i) * E(h_q)^-1 = E(h_i - h_q); decrypts to 0 only on a match.
    n = keys["n"]
    query = paillier_raw_encrypt(int(term_hash(term), 16), n)
    inverse = pow(query, -1, n * n)
    return any(paillier_raw_decrypt(e * inverse % (n * n), keys) == 0 for e in entries)


# ---------------- verification pipeline ----------------
def check_package(record_id, submitter, package):
    """Decrypt and verify a client package. Returns (ok, details, record)."""
    group, he_public = load("keys/group.json"), load("keys/he_public.json")
    details = {"Record ID": record_id, "Submitted by": submitter}
    try:
        key = unwrap_key(package["wrapped_key"], load("keys/wrap_private.json"), group)
        details["Session key unwrapped (" + ALG["wrap"] + ")"] = key.hex()
        payload = json.loads(sym_decrypt(key, package["encrypted"]))
        record = normalize_record(payload["record"])
    except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        details["Decryption"] = "FAILED (" + type(error).__name__ + ")"
        return False, details, None
    details[ALG["cipher"] + "-" + ALG["mode"] + " decryption"] = "OK"
    computed = digest_text(record_text(record_id, record))
    hash_ok = hmac.compare_digest(str(package["digest"]), computed)
    details["Received " + ALG["hash"]] = package["digest"]
    details["Computed " + ALG["hash"]] = computed
    details["Hash comparison"] = "MATCH" if hash_ok else "MISMATCH"
    ok = hash_ok
    if CONFIG["hash_field"]:
        part = field_digest(record)
        part_ok = hmac.compare_digest(str(package.get("field_digest")), part)
        details["Received " + ALG["hash"] + " of " + CONFIG["hash_field"]] = package.get("field_digest")
        details["Computed " + ALG["hash"] + " of " + CONFIG["hash_field"]] = part
        details[CONFIG["hash_field"] + " hash comparison"] = "MATCH" if part_ok else "MISMATCH"
        ok = ok and part_ok
    sig_ok, sig_details = verify_digest(computed, package["signature"], package["signer_public"], group)
    details.update(sig_details)
    details[ALG["signature"] + " signature"] = "VALID" if sig_ok else "INVALID"
    ok = ok and sig_ok
    he = package["homomorphic"]
    he_ok = set(he) == set(METRICS) and set(payload.get("randomness", {})) == set(METRICS)
    if he_ok:
        for name, value in metric_values(record).items():
            try:
                he_ok = he_ok and he_matches(encode_metric(name, value), payload["randomness"][name], he[name], he_public)
            except ValueError:
                he_ok = False
    details[ALG["homomorphic"] + " ciphertexts match the signed record"] = he_ok
    details["Individual homomorphic values"] = "kept encrypted (never decrypted)"
    return ok and he_ok, details, record


def verify_stored(record_id):
    record_id = check_id(record_id)
    if not exists(f"records/{record_id}.json"):
        raise ValueError("Record not found: " + record_id)
    stored = load(f"records/{record_id}.json")
    ok, details, record = check_package(record_id, stored["submitter"], stored["package"])
    signers = load("keys/signers.json") if exists("keys/signers.json") else {}
    signer_ok = signers.get(stored["submitter"]) == stored["package"]["signer_public"]
    tsa_ok = tsa_valid(record_id, stored["package"]["digest"], stored["timestamp"], stored["tsa_signature"])
    period_ok = in_period(stored["timestamp"]) and stored["timestamp"] <= now()
    details["Signer key registered for submitter"] = signer_ok
    details["Timestamp (IST)"] = stored["timestamp"]
    details["Timestamp authority signature"] = "VALID" if tsa_ok else "INVALID"
    details["Within submission period"] = period_ok
    index_ok = record is not None and plain_index(stored["index"]) == expected_plain_index(record)
    details["Search index consistent"] = index_ok
    ok = ok and signer_ok and tsa_ok and period_ok and index_ok
    details["Result"] = "VERIFIED" if ok else "REJECTED - record or metadata was tampered with"
    return ok, details, record, stored


# ---------------- actions ----------------
def do_submit(username, req):
    record_id = check_id(req.get("id", ""))
    if exists(f"records/{record_id}.json"):
        raise ValueError("Record ID already exists: " + record_id)
    if CONFIG["close_on_tally"] and exists("tally/aggregate.json"):
        raise ValueError("Submissions are closed: the tally has been computed.")
    package = req["package"]
    timestamp = now()
    if not in_period(timestamp):
        settings = load("keys/settings.json")
        raise ValueError(f"Submission at {timestamp} is outside the period {settings['start']} to {settings['deadline']}.")
    signers = load("keys/signers.json") if exists("keys/signers.json") else {}
    if username in signers and signers[username] != package["signer_public"]:
        raise ValueError("Signing key does not match the key registered for " + username + ".")
    ok, details, record = check_package(record_id, username, package)
    if not ok:
        details["Result"] = "REJECTED"
        return {"status": "error", "message": "Verification failed; record rejected.", "details": details}
    signature = tsa_sign(record_id, package["digest"], timestamp)
    save(f"records/{record_id}.json", {"id": record_id, "submitter": username, "package": package,
                                      "timestamp": timestamp, "tsa_signature": signature,
                                      "index": build_index(record)})
    signers[username] = package["signer_public"]
    save("keys/signers.json", signers)
    details["Trusted timestamp (IST)"] = timestamp
    details["Timestamp authority signature"] = signature
    details["Within submission period"] = True
    details["Search index"] = "built (" + ALG["search"] + ")"
    details["Result"] = "ACCEPTED and stored"
    return {"status": "ok", "message": "Record accepted.", "details": details,
            "timestamp": timestamp, "tsa_signature": signature}


def do_search(req):
    if req.get("field") == "__time__":
        start = datetime.strptime(str(req.get("start", "")).strip(), TIME_FORMAT).strftime(TIME_FORMAT)
        end = datetime.strptime(str(req.get("end", "")).strip(), TIME_FORMAT).strftime(TIME_FORMAT)
        if end < start:
            raise ValueError("End time is before start time.")
        ids = [r["id"] for r in all_records() if start <= r["timestamp"] <= end]
        return {"status": "ok", "search": f"time range {start} to {end}", "matching_ids": ids or "No matches"}
    field = next((f for f in CONFIG["fields"] if f["name"] == req.get("field") and f["search"] != "none"), None)
    if field is None:
        raise ValueError("That field is not searchable.")
    term = query_term(field, req.get("query", ""))
    ids = [r["id"] for r in all_records() if index_match(r["index"].get(field["name"], []), term)]
    return {"status": "ok", "search": field["name"] + " = " + str(req.get("query", "")).strip(),
            "method": ALG["search"] + " (record contents stay encrypted)", "matching_ids": ids or "No matches"}


def all_records():
    folder = BASE / "records"
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))] if folder.exists() else []


def build_aggregate(ids):
    he_public = load("keys/he_public.json")
    if not ids:
        ids = [r["id"] for r in all_records()]
    ids = [check_id(i) for i in ids]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate record ID in selection.")
    if len(ids) < CONFIG["min_records"]:
        raise ValueError(f"Select at least {CONFIG['min_records']} records.")
    totals = {name: he_identity() for name in METRICS}
    for record_id in ids:
        ok, _, _, stored = verify_stored(record_id)
        if not ok:
            raise ValueError(record_id + " failed verification; it cannot be tallied.")
        for name in METRICS:
            totals[name] = he_combine(totals[name], stored["package"]["homomorphic"][name], he_public)
    check_capacity(len(ids), he_public)
    return {"ids": ids, "ciphertexts": totals}


def do_tally(req):
    aggregate = build_aggregate([i.strip() for i in req.get("ids", []) if str(i).strip()])
    save("tally/aggregate.json", aggregate)
    return {"status": "ok", "included_ids": aggregate["ids"],
            "operation": "Homomorphic " + ("addition" if he_additive() else "multiplication") + " of ciphertexts",
            "combined_ciphertexts_hex": {METRICS[n]["label"]: he_hex(c) for n, c in aggregate["ciphertexts"].items()},
            "note": "No individual value was decrypted."}


def do_decrypt(req):
    if not exists("tally/aggregate.json"):
        raise ValueError("Compute the tally first.")
    aggregate = load("tally/aggregate.json")
    if build_aggregate(aggregate["ids"]) != aggregate:
        raise ValueError("Stored aggregate is stale or was altered; run the tally again.")
    he_public = load("keys/he_public.json")
    if CONFIG["threshold"]:
        passwords = req.get("passwords", [])
        if len(passwords) != 2:
            raise ValueError("Both authority passwords are required.")
        exponents = [unprotect(load(f"keys/authority_{i}.json"), passwords[i - 1]) for i in (1, 2)]
    else:
        exponents = [load("keys/he_private.json")["d"]]
    partials, results = {}, {}
    for name, ciphertext in aggregate["ciphertexts"].items():
        parts = [he_partial(ciphertext, e, he_public) for e in exponents]
        partials[METRICS[name]["label"]] = [hex(p) for p in parts]
        results[METRICS[name]["label"]] = decode_metric(name, he_join(ciphertext, parts, he_public))
    if results["Record count"] != len(aggregate["ids"]):
        raise ValueError("Aggregate record count mismatch.")
    for field in CONFIG["fields"]:
        labels = [m["label"] for m in METRICS.values() if m.get("field") == field["name"] and m["kind"] == "count"]
        if labels and sum(results[l] for l in labels) != len(aggregate["ids"]):
            raise ValueError("Category counts do not add up to the record count.")
    save("tally/final_results.json", {"completed_at": now(), "ids": aggregate["ids"], "results": results})
    return {"status": "ok", "included_ids": aggregate["ids"],
            "decryption": "2-of-2 threshold (authority 1 + authority 2 partials)" if CONFIG["threshold"] else "single key",
            "partial_decryptions": partials if CONFIG["threshold"] else "n/a", "results": results,
            "note": "Only the final aggregate ciphertext was decrypted."}


def he_demo(a, b):
    with LOCK:
        if "he" not in DEMO_KEYS:
            group = load("keys/group.json")
            DEMO_KEYS["he"] = he_keygen(group)
    public, secret, _ = DEMO_KEYS["he"]
    if not he_additive() and (a < 1 or b < 1):
        raise ValueError("Multiplicative schemes need integers of at least 1.")
    ca, _ = he_encrypt(a, public)
    cb, _ = he_encrypt(b, public)
    combined = he_combine(ca, cb, public)
    result = he_join(combined, [he_partial(combined, secret, public)], public)
    return {"scheme": ALG["homomorphic"], "operation": "addition" if he_additive() else "multiplication",
            "encrypted_a": he_hex(ca), "encrypted_b": he_hex(cb), "encrypted_result": he_hex(combined),
            "decrypted_result": result, "expected": a + b if he_additive() else a * b}


def handle(username, role, req):
    action = req.get("action", "")
    if action not in CONFIG["roles"].get(role, []):
        audit(username, role, action, "DENIED")
        return {"status": "error", "message": f"Permission denied: role '{role}' cannot perform '{action}'."}
    try:
        with LOCK:
            if action == "submit":
                response = do_submit(username, req)
            elif action in ("verify", "view"):
                ok, details, record, _ = verify_stored(req.get("id", ""))
                response = {"status": "ok" if ok else "error", "details": details}
                if action == "view":
                    response["plaintext"] = record if ok else "withheld: verification failed"
            elif action == "list":
                response = {"status": "ok", "records": [{"id": r["id"], "submitter": r["submitter"], "timestamp": r["timestamp"]}
                                                        for r in all_records()] or "No records"}
            elif action == "search":
                response = do_search(req)
            elif action == "tally":
                response = do_tally(req)
            elif action == "decrypt":
                response = do_decrypt(req)
            elif action == "audit":
                lines = (BASE / "audit.log").read_text(encoding="utf-8").splitlines() if exists("audit.log") else []
                response = {"status": "ok", "log": [json.loads(line) for line in lines[-50:]]}
            elif action == "classical":
                response = {"status": "ok", **classical_demo(str(req.get("text", "")))}
            elif action == "he_demo":
                response = {"status": "ok", **he_demo(int(req.get("a")), int(req.get("b")))}
            elif action == "tamper":
                record_id = check_id(req.get("id", ""))
                if not exists(f"records/{record_id}.json"):
                    raise ValueError("Record not found: " + record_id)
                stored = load(f"records/{record_id}.json")
                ct = stored["package"]["encrypted"]["ciphertext"]
                stored["package"]["encrypted"]["ciphertext"] = ("0" if ct[0] != "0" else "1") + ct[1:]
                save(f"records/{record_id}.json", stored)
                response = {"status": "ok", "message": f"Stored ciphertext of {record_id} modified. Verify it now."}
            else:
                response = {"status": "error", "message": "Unknown action."}
    except (ValueError, KeyError, TypeError, OSError) as error:
        response = {"status": "error", "message": str(error)}
    audit(username, role, action, response["status"].upper(), str(req.get("id", "")))
    print(f"\n[{now()}] {username}/{role} -> {action}: {response['status']}")
    if "details" in response:
        for name, value in response["details"].items():
            print(f"  {name}: {value}")
    return response


# ---------------- networking ----------------
def client_thread(conn, address):
    username, role = "unknown", "unknown"
    try:
        with conn, conn.makefile("rwb") as stream:
            login = recv_json(stream) or {}
            username = str(login.get("username", ""))
            user = CONFIG["users"].get(username)
            password = str(login.get("password", ""))
            if not user or not hmac.compare_digest(password_key(password, bytes.fromhex(user["salt"])).hex(), user["hash"]):
                audit(username, "unknown", "login", "FAILED")
                send_json(stream, {"status": "error", "message": "Invalid username or password."})
                return
            role = user["role"]
            audit(username, role, "login", "SUCCESS")
            print(f"[{now()}] {username} logged in as {role} from {address[0]}:{address[1]}")
            send_json(stream, {"status": "ok", "role": role, "actions": CONFIG["roles"][role], "bundle": bundle()})
            while True:
                req = recv_json(stream)
                if req is None or req.get("action") == "logout":
                    break
                send_json(stream, handle(username, role, req))
    except (ConnectionError, OSError, json.JSONDecodeError, UnicodeError):
        pass
    finally:
        print(f"[{now()}] connection closed: {username}/{role}")


def main():
    setup()
    host, port = CONFIG["host"], CONFIG["port"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        print(f"\n{CONFIG['title']} SERVER listening on {host}:{port}")
        print("Accounts: " + ", ".join(f"{u} ({v['role']})" for u, v in CONFIG["users"].items()))
        print("Stored records: " + str(len(all_records())))
        while True:
            conn, address = server.accept()
            threading.Thread(target=client_thread, args=(conn, address), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer stopped.")
'''


# =====================================================================
# client.py
# =====================================================================
CLIENT = r'''"""CLIENT - start server.py first, then:  python client.py
Hashes, signs, encrypts (session key + server public key) and homomorphically
encrypts on the client before anything is sent."""
import getpass
import json
import socket
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from common import *

KEY_DIR = Path(__file__).resolve().parent / "client_data"
LABELS = {
    "submit": "Submit " + CONFIG["record_name"], "verify": "Verify stored " + CONFIG["record_name"],
    "view": "View " + CONFIG["record_name"] + " (verify + decrypt)", "list": "List " + CONFIG["record_name"] + "s",
    "search": "Search", "tally": "Homomorphic tally (" + ALG["homomorphic"] + ")",
    "decrypt": "Decrypt final aggregate" + (" (threshold)" if CONFIG["threshold"] else ""),
    "audit": "Audit log", "classical": ALG["classical"] + " cipher demo",
    "he_demo": ALG["homomorphic"] + " homomorphic demo", "tamper": "Tamper demo (corrupt stored record)",
}


def signing_key(username, group):
    # Each user keeps a private signing key on the client; the server registers the public key.
    path = KEY_DIR / (username + "_signing.json")
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    KEY_DIR.mkdir(exist_ok=True)
    print("Generating " + ALG["signature"] + " signing key for " + username + "...")
    private, public = signing_keygen(group)
    keys = {"private": private, "public": public}
    path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return keys


def build_package(record_id, values, username, bundle):
    record = normalize_record(values)
    group, he_public = bundle["group"], bundle["he"]
    outputs = {"Record ID": record_id}
    digest = digest_text(record_text(record_id, record))
    outputs[ALG["hash"] + " of record"] = digest
    part = field_digest(record)
    if part is not None:
        outputs[ALG["hash"] + " of " + CONFIG["hash_field"]] = part
    keys = signing_key(username, group)
    signature = sign_digest(digest, keys["private"], group)
    outputs[ALG["signature"] + " signature"] = signature
    encrypted, randomness = {}, {}
    for name, value in metric_values(record).items():
        encrypted[name], randomness[name] = he_encrypt(encode_metric(name, value), he_public)
    outputs[ALG["homomorphic"] + " ciphertexts (hex)"] = {METRICS[n]["label"]: he_hex(c) for n, c in encrypted.items()}
    # The randomness travels inside the encrypted payload so the server can check the
    # homomorphic ciphertexts by re-encryption without ever decrypting them.
    key = session_key()
    packet = sym_encrypt(key, canonical({"record": record, "randomness": randomness}))
    outputs[ALG["cipher"] + " session key"] = key.hex()
    outputs["IV / nonce (hex)"] = packet["iv"] or "none (ECB)"
    outputs[ALG["cipher"] + "-" + ALG["mode"] + " ciphertext (hex)"] = packet["ciphertext"]
    wrapped = wrap_key(key, bundle["wrap"], group)
    outputs["Session key protected with " + ALG["wrap"]] = wrapped
    show("CLIENT-SIDE PROCESSING", outputs)
    return {"encrypted": packet, "wrapped_key": wrapped, "digest": digest, "field_digest": part,
            "signature": signature, "signer_public": keys["public"], "homomorphic": encrypted}


def ask_request(action, bundle, username):
    if action == "submit":
        record_id = check_id(input(CONFIG["record_name"] + " ID: "))
        values = {}
        for field in CONFIG["fields"]:
            hint = " (" + ", ".join(field["choices"]) + ")" if field["type"] == "choice" else ""
            values[field["name"]] = input(field["name"] + hint + ": ")
        return {"action": action, "id": record_id, "package": build_package(record_id, values, username, bundle)}
    if action in ("verify", "view", "tamper"):
        return {"action": action, "id": input(CONFIG["record_name"] + " ID: ").strip()}
    if action == "search":
        fields = [f for f in CONFIG["fields"] if f["search"] != "none"]
        for number, field in enumerate(fields, 1):
            print(f"{number}. {field['name']} ({'one word' if field['search'] == 'words' else 'exact value'})")
        print(f"{len(fields) + 1}. Submission time range")
        choice = input("Search by: ").strip()
        if choice == str(len(fields) + 1):
            print("Use YYYY-MM-DD HH:MM:SS (IST).")
            return {"action": action, "field": "__time__", "start": input("Start: "), "end": input("End: ")}
        if not choice.isdigit() or not 1 <= int(choice) <= len(fields):
            raise ValueError("Invalid search choice.")
        return {"action": action, "field": fields[int(choice) - 1]["name"], "query": input("Search value: ")}
    if action == "tally":
        ids = input(CONFIG["record_name"] + " IDs to tally (comma separated, Enter = all): ")
        return {"action": action, "ids": [i.strip() for i in ids.split(",") if i.strip()]}
    if action == "decrypt":
        if CONFIG["threshold"]:
            return {"action": action, "passwords": [getpass.getpass("Authority 1 password: "),
                                                    getpass.getpass("Authority 2 password: ")]}
        return {"action": action}
    if action == "classical":
        return {"action": action, "text": input("Text (English letters): ")}
    if action == "he_demo":
        return {"action": action, "a": int(input("First integer: ")), "b": int(input("Second integer: "))}
    return {"action": action}


def main():
    print(CONFIG["title"] + " - CLIENT")
    username, password = input("Username: ").strip(), getpass.getpass("Password: ")
    with socket.create_connection((CONFIG["host"], CONFIG["port"])) as sock, sock.makefile("rwb") as stream:
        send_json(stream, {"username": username, "password": password})
        reply = recv_json(stream)
        if not reply or reply.get("status") != "ok":
            print(reply.get("message") if reply else "No reply from server.")
            return
        actions, bundle = reply["actions"], reply["bundle"]
        print("Logged in as " + reply["role"])
        while True:
            print("\n------ " + reply["role"].upper() + " MENU ------")
            for number, action in enumerate(actions, 1):
                print(f"{number}. {LABELS[action]}")
            print(f"{len(actions) + 1}. Logout")
            choice = input("Enter choice: ").strip()
            if choice == str(len(actions) + 1):
                send_json(stream, {"action": "logout"})
                break
            if not choice.isdigit() or not 1 <= int(choice) <= len(actions):
                print("Invalid choice.")
                continue
            try:
                request = ask_request(actions[int(choice) - 1], bundle, username)
            except ValueError as error:
                print("Invalid input:", error)
                continue
            send_json(stream, request)
            response = recv_json(stream)
            if response is None:
                print("Server closed the connection.")
                break
            print("\n=== SERVER RESPONSE ===")
            print(json.dumps(response, indent=2, ensure_ascii=False))
            if request["action"] == "submit" and response.get("status") == "ok":
                # The client can check the trusted timestamp itself with the TSA public key.
                message = SHA256.new(canonical({"id": request["id"], "digest": request["package"]["digest"],
                                                "timestamp": response["timestamp"]}).encode())
                try:
                    pkcs1_15.new(RSA.import_key(bundle["tsa"])).verify(message, bytes.fromhex(response["tsa_signature"]))
                    print("Client check: timestamp authority signature VALID")
                except ValueError:
                    print("Client check: timestamp authority signature INVALID")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nClient closed.")
    except ConnectionRefusedError:
        print("Cannot connect: start server.py first.")
'''


# =====================================================================
# generator logic
# =====================================================================
def make_metrics(fields, homomorphic):
    additive = homomorphic in ("Paillier", "ElGamal-Exp")
    metrics = {"record_count": {"kind": "record_count", "label": "Record count"}}
    for i, field in enumerate(fields):
        if field.get("total"):
            metrics[f"total_{i}"] = {"kind": "sum" if additive else "product", "field": field["name"],
                                     "label": ("Total " if additive else "Product ") + field["name"]}
        if field.get("count"):
            for j, choice in enumerate(field["choices"]):
                metrics[f"count_{i}_{j}"] = {"kind": "count", "field": field["name"], "choice": choice,
                                             "label": field["name"] + " = " + choice}
    return metrics


def hash_password(password):
    salt = os.urandom(16)
    return {"salt": salt.hex(), "hash": hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32).hex()}


def validate_config(config):
    fields = config["fields"]
    if not 1 <= len(fields) <= 30:
        raise ValueError("Configure 1 to 30 fields.")
    seen = set()
    for field in fields:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,39}", field["name"]) or field["name"].casefold() in seen:
            raise ValueError("Field names must be unique, start with a letter, and use letters/digits/_.")
        seen.add(field["name"].casefold())
        if field["type"] not in ("text", "integer", "choice"):
            raise ValueError("Field type must be text, integer or choice.")
        if field["search"] not in ("none", "exact", "words") or (field["search"] == "words" and field["type"] != "text"):
            raise ValueError("Search must be none/exact (any field) or words (text fields).")
        if field.get("total") and not (field["type"] == "integer" or
                                       (field["type"] == "choice" and all(c.isdigit() for c in field["choices"]))):
            raise ValueError("Encrypted totals need an integer field or a choice field with numeric choices.")
        if field.get("count") and field["type"] != "choice":
            raise ValueError("Per-choice counts need a choice field.")
    if config["hash_field"] is not None and config["hash_field"] not in {f["name"] for f in fields}:
        raise ValueError("The separately hashed field must be a configured field.")
    if not config["roles"] or not config["users"]:
        raise ValueError("Configure at least one role.")
    for role, actions in config["roles"].items():
        if any(a not in ACTIONS for a in actions):
            raise ValueError("Unknown action for role " + role)
    if "classical" in {a for acts in config["roles"].values() for a in acts} and config["algorithms"]["classical"] == "none":
        raise ValueError("A role has the classical demo but no classical cipher was chosen.")
    return config


def build_sources(config):
    config = validate_config(config)
    common = COMMON.replace("__CONFIG__", repr(config), 1)
    for source in (common, SERVER, CLIENT):
        ast.parse(source)
    if config["algorithms"]["classical"] != "none":
        namespace = {}
        exec(compile(common, "common.py", "exec"), namespace)
        result = namespace["classical_demo"]("CRYPTOGRAPHY")
        if namespace["letters_only"](result["decrypted"]).rstrip("X") != "CRYPTOGRAPHY":
            raise ValueError("Classical cipher self-test failed; check the key.")
    return common


def create_solution(config, output_dir):
    common = build_sources(config)
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    readable = {k: v for k, v in config.items() if k != "users"}
    readable["users"] = {u: v["role"] for u, v in config["users"].items()}
    files = {
        "common.py": common, "server.py": SERVER, "client.py": CLIENT,
        "config.json": json.dumps(readable, indent=2, ensure_ascii=False),
        "requirements.txt": "pycryptodome\n",
        ".gitignore": "server_data/\nclient_data/\n__pycache__/\n",
        "RUN.txt": run_text(config),
    }
    for name, content in files.items():
        (directory / name).write_text(content, encoding="utf-8")
    return directory


def run_text(config):
    alg = config["algorithms"]
    roles = "\n".join(f"  {u} ({v['role']}): {', '.join(config['roles'][v['role']])}" for u, v in config["users"].items())
    return f"""{config['title']} - CLIENT/SERVER SOLUTION

INSTALL   python -m pip install -r requirements.txt
TERMINAL 1   python server.py   (first run: {'submission period dates, ' if config['use_deadline'] else ''}{'two authority passwords, ' if config['threshold'] else ''}key generation)
TERMINAL 2   python client.py   (log in; the menu shows only that role's actions)
Open more client terminals to log in as other roles at the same time.

ACCOUNTS (usernames; passwords were set in the generator)
{roles}

ALGORITHMS
  Classical demo   : {alg['classical']} (key {alg['classical_key']})
  Symmetric        : {alg['cipher']}-{alg['mode']} with a fresh session key per record
  Key protection   : {alg['wrap']}{' (' + str(alg['rsa_bits']['wrap']) + '-bit)' if alg['wrap'] == 'RSA' else ''}
  Hash             : {alg['hash']} over the canonical record (ID + all fields){', plus ' + config['hash_field'] + ' alone' if config['hash_field'] else ''}
  Signature        : {alg['signature']}, signed on the client over the digest
  Homomorphic      : {alg['homomorphic']} ({'sum' if alg['homomorphic'] in ('Paillier', 'ElGamal-Exp') else 'product'}), encrypted on the client
  Search           : {alg['search']}{' / ' + alg['sse_cipher'] if alg['search'] == 'SSE' else ''}
  Timestamp        : server timestamp authority signs (ID, digest, time) with RSA-2048
  Final decryption : {'2-of-2 threshold (two authority passwords)' if config['threshold'] else 'single key held by the server'}

FLOW
  Client: hash -> sign -> homomorphic-encrypt numeric values -> encrypt record with the
          session key -> protect the session key with the server's public key -> send.
  Server: unwrap key -> decrypt -> recompute and compare hash -> verify signature ->
          check homomorphic ciphertexts by re-encryption (never decrypts them) ->
          trusted timestamp + period check -> build search index -> store.
  Tally : multiply ciphertexts of selected (or all) verified records.
  Decrypt: only the final aggregate is decrypted.

Data persists in server_data/ (server) and client_data/ (signing keys). Delete both
folders to start fresh. Local TCP, demo passwords: a lab simulation, not production.
"""


# ---------------- interactive prompts ----------------
def ask(prompt, default=None):
    answer = input(prompt + (f" [{default}]" if default is not None else "") + ": ").strip()
    return answer if answer else (default if default is not None else "")


def ask_yes(prompt, default=False):
    while True:
        answer = input(prompt + (" [Y/n]: " if default else " [y/N]: ")).strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes", "n", "no"):
            return answer.startswith("y")
        print("Enter y or n.")


def ask_number(prompt, low, high, default=None):
    while True:
        answer = ask(prompt, default)
        if str(answer).isdigit() and low <= int(answer) <= high:
            return int(answer)
        print(f"Enter a number from {low} to {high}.")


def ask_choice(category):
    choices = ALGORITHM_CHOICES[category]
    print(CATEGORY_LABELS[category] + ": " + ", ".join(f"{i}. {c}" for i, c in enumerate(choices, 1)))
    return choices[ask_number("  choice", 1, len(choices), 1) - 1]


def choose_fields():
    fields = []
    for i in range(ask_number("Number of record fields (not counting the ID)", 1, 30)):
        while True:
            name = ask(f"Field {i + 1} name (e.g. candidate_id, constituency, content)")
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,39}", name) and name.casefold() not in {f["name"].casefold() for f in fields}:
                break
            print("Use a unique name: letters/digits/_, starting with a letter.")
        while True:
            kind = ask("  Type: text / integer / choice").lower()
            if kind in ("text", "integer", "choice"):
                break
        field = {"name": name, "type": kind, "search": "none", "total": False, "count": False}
        if kind == "choice":
            while True:
                choices = [c.strip() for c in ask("  Allowed choices, comma separated").split(",")]
                if all(choices) and len({c.casefold() for c in choices}) == len(choices) and len(choices) <= 30:
                    field["choices"] = choices
                    break
                print("  Enter unique, nonempty choices.")
        if kind == "text":
            while True:
                search = ask("  Search on this field: none / exact / words", "none").lower()
                if search in ("none", "exact", "words"):
                    field["search"] = search
                    break
        else:
            field["search"] = "exact" if ask_yes("  Allow exact-value search on this field?") else "none"
        numeric_choice = kind == "choice" and all(c.isdigit() for c in field["choices"])
        if kind == "integer" or numeric_choice:
            field["total"] = ask_yes("  Homomorphic encrypted total of this value (sum or product)?")
        if kind == "choice":
            field["count"] = ask_yes("  Homomorphic encrypted count for each choice?")
        fields.append(field)
    return fields


def choose_algorithms():
    print("\nCHOOSE ALGORITHMS (number; Enter = first option)")
    alg = {"rsa_bits": dict(RSA_DEFAULT_BITS)}
    for category in ("classical", "cipher", "mode", "hash", "wrap", "signature", "search", "homomorphic"):
        alg[category] = ask_choice(category)
        if category == "classical":
            alg["classical_key"] = ""
            if alg["classical"] != "none":
                alg["classical_key"] = ask("  " + alg["classical"] + " key", CLASSICAL_DEFAULT_KEYS[alg["classical"]])
        if category == "search":
            alg["sse_cipher"] = ask_choice("sse_cipher") if alg["search"] == "SSE" else "HMAC-SHA256"
        purpose = {"wrap": "wrap", "signature": "signature", "homomorphic": "homomorphic"}.get(category)
        if purpose and alg[category] in ("RSA", "RSA-PSS"):
            while True:
                bits = ask(f"  RSA bits for {category}: 1024 / 2048 / 3072 / 4096", RSA_DEFAULT_BITS[purpose])
                if str(bits).isdigit() and int(bits) in RSA_KEY_SIZES:
                    alg["rsa_bits"][purpose] = int(bits)
                    break
    return alg


def choose_roles():
    names = list(ACTIONS)
    roles, users = {}, {}
    for i in range(ask_number("Number of roles", 1, 20)):
        while True:
            role = ask(f"Role {i + 1} name (e.g. voter, server, tally)").strip()
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_ -]{0,30}", role) and role not in roles:
                break
            print("Use a unique role name (letters, digits, space, _ or -).")
        print("Actions: " + "  ".join(f"{n}. {a}" for n, a in enumerate(names, 1)))
        while True:
            answer = ask("  Allowed actions (comma-separated numbers, or all)").lower()
            if answer == "all":
                picked = names
                break
            try:
                numbers = [int(x) for x in answer.split(",") if x.strip()]
            except ValueError:
                numbers = []
            if numbers and all(1 <= n <= len(names) for n in numbers):
                picked = [names[n - 1] for n in numbers]
                break
            print("  Enter numbers from the list, e.g. 1,2,5")
        roles[role] = [a for a in names if a in picked]
        default_user = re.sub(r"[^a-z0-9]", "", role.lower()) or f"user{i + 1}"
        while True:
            username = ask("  Username for this role", default_user)
            if re.fullmatch(r"[A-Za-z0-9_]{1,30}", username) and username not in users:
                break
            print("  Use a unique username (letters, digits, _).")
        users[username] = {"role": role, **hash_password(ask("  Password", username + "123"))}
    return roles, users


def main():
    print("CLIENT/SERVER CRYPTO LAB GENERATOR")
    print("Generates server.py + client.py + common.py with client-side hashing, signing and")
    print("encryption, server-side verification, timestamps, search, tally and decryption.\n")
    title = ask("System title (e.g. Secure E-Voting)") or "Secure Client Server System"
    record_name = ask("Record name (e.g. ballot, document, report)", "record")
    fields = choose_fields()
    hash_field = None
    if ask_yes("Also hash one field on its own (e.g. a document digest)?"):
        for i, field in enumerate(fields, 1):
            print(f"  {i}. {field['name']}")
        hash_field = fields[ask_number("  Field to hash", 1, len(fields)) - 1]["name"]
    use_deadline = ask_yes("Enforce a submission period / deadline (dates asked on first server run)?")
    close_on_tally = ask_yes("Close submissions once the tally is computed?")
    threshold = ask_yes("Threshold decryption: two authority passwords needed to decrypt the final total?")
    min_records = ask_number("Minimum records in a tally", 1, 100000, 2)
    algorithms = choose_algorithms()
    print("\nROLES AND ACCOUNTS")
    roles, users = choose_roles()
    port = ask_number("Server port", 1024, 65535, 5200)
    config = {"title": title, "record_name": record_name, "fields": fields, "hash_field": hash_field,
              "use_deadline": use_deadline, "close_on_tally": close_on_tally, "threshold": threshold,
              "min_records": min_records, "algorithms": algorithms, "metrics": make_metrics(fields, algorithms["homomorphic"]),
              "roles": roles, "users": users, "host": "127.0.0.1", "port": port}
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", title).strip("_")[:60] or "solution"
    default = Path(__file__).resolve().parent / "GENERATED_SERVER_CLIENT" / slug
    while True:
        answer = ask("NEW output folder", str(default))
        try:
            directory = create_solution(config, Path(answer).expanduser())
            break
        except FileExistsError:
            print("Folder exists; choose a new one so existing data is kept.")
        except (OSError, ValueError) as error:
            print("Could not create solution:", error)
            if isinstance(error, ValueError):
                return
    print("\nCreated:", directory)
    print("Terminal 1: cd into it, python server.py")
    print("Terminal 2: same folder, python client.py")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGenerator closed.")
