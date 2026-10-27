"""
====================================================================
 UNIVERSAL EXAM TEMPLATE
====================================================================
One menu/role/storage skeleton that NEVER needs to change, sitting on
top of a library of every confidentiality, signature, and hash
algorithm taught in this course (Labs 1-6), plus optional toggleable
extensions for key exchange, homomorphic tallying, searchable
encryption, and timestamp checking (Labs 3/7/8).

HOW TO USE THIS IN THE EXAM:
  1. Read the question. Decide which confidentiality algorithm,
     signature algorithm, and hash algorithm it wants (or "NONE" for
     signature if it doesn't ask for one).
  2. Edit ONLY the CONFIG block directly below - nothing else in this
     file needs to change for the combination to work.
  3. Run the file. Login as Student, Faculty, or HoD exactly like every
     other BIG_SYSTEMS file in this kit.

CONFIDENTIALITY_ALGO options:
    Classical (Lab 1): ADDITIVE, MULTIPLICATIVE, AFFINE, VIGENERE,
                        AUTOKEY, PLAYFAIR, HILL, TRANSPOSITION
    Symmetric (Lab 2):  DES, AES128, AES192, AES256, 3DES  (all CBC mode)
    Asymmetric (Lab 3/4/7): RSA, ELGAMAL, ECC, RABIN, PAILLIER

SIGNATURE_ALGO options (Lab 6): RSA, ELGAMAL, SCHNORR, ECDSA, RABIN, NONE

HASH_ALGO options (Lab 5): SHA256, SHA1, SHA512, MD5, CUSTOM

OPTIONAL EXTENSIONS (all default OFF - turn on only what the question asks):
    ENABLE_KEY_EXCHANGE      - derive the symmetric key via DH or ECDH
                                instead of generating it directly.
                                Only meaningful when CONFIDENTIALITY_ALGO
                                is DES/AES128/AES192/AES256/3DES.
    ENABLE_SEARCHABLE_INDEX  - Lab 8: Faculty can search uploaded records
                                by keyword via a deterministic HMAC index,
                                without ever exposing record content to
                                the search operation itself.
    ENABLE_TIMESTAMP_CHECK   - every upload gets a timestamp; Faculty's
                                verification step also reports whether it
                                falls inside a configurable time window.
    ENABLE_HOMOMORPHIC_DEMO  - Lab 7: adds a "submit a numeric value"
                                Student action and a "tally without
                                decrypting" Faculty action. ONLY valid
                                when CONFIDENTIALITY_ALGO is PAILLIER
                                (addition) or ELGAMAL/RSA (multiplication).
    ENABLE_THRESHOLD_DECRYPT - the final homomorphic tally can only be
                                opened once a configurable number of
                                "election authorities" each supply their
                                key share (simplified n-of-n demo - see
                                BIG_SYSTEMS/secureEVoting_*.py for the
                                full writeup of why this is simplified).
                                ONLY valid together with
                                ENABLE_HOMOMORPHIC_DEMO and
                                CONFIDENTIALITY_ALGO == "PAILLIER".

WHY THIS FILE KEEPS EVERYTHING IN MEMORY (no JSON/pickle database file
like the other BIG_SYSTEMS files): different backends use wildly
different key material - raw ints for classical/ElGamal/Rabin/Paillier,
PyCryptodome RSA key objects, `cryptography` library EC key objects.
Serializing all of those to one JSON schema for every possible
combination would multiply the testing surface for no real benefit: in
an exam you run this script ONCE and go Student -> Faculty -> HoD in a
single sitting, exactly like every other file in this kit is actually
used. If you genuinely need records to survive separate script runs,
copy the serialization pattern from the matching BIG_SYSTEMS file for
your chosen algorithm instead.

HEX RULE: every intermediate and final value is shown in hex, same as
the rest of this kit.
====================================================================
"""

# ======================= CONFIG - EDIT THIS ========================
CONFIDENTIALITY_ALGO = "AES256"
SIGNATURE_ALGO = "RSA"
HASH_ALGO = "SHA256"

ENABLE_KEY_EXCHANGE = False
KEY_EXCHANGE_ALGO = "DH"          # "DH" or "ECDH" - only used if enabled above

ENABLE_SEARCHABLE_INDEX = False
ENABLE_TIMESTAMP_CHECK = False
TIMESTAMP_WINDOW_MINUTES = 60

ENABLE_HOMOMORPHIC_DEMO = False    # requires CONFIDENTIALITY_ALGO in (PAILLIER, ELGAMAL, RSA)
ENABLE_THRESHOLD_DECRYPT = False   # requires the above AND CONFIDENTIALITY_ALGO == "PAILLIER"
THRESHOLD_AUTHORITIES = 3
# =====================================================================

import os
import json
import random
import math
import hashlib
import hmac as hmac_lib
from datetime import datetime

from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as PC_SHA256

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# ======================================================================
# SHARED HELPERS
# ======================================================================
def is_prime(n, rounds=20):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(c):
            return c


def gen_blum_prime(bits):
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if c % 4 == 3 and is_prime(c):
            return c


def letters_only_upper(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch.isalpha())


# ======================================================================
# CLASSICAL CIPHER CORE FUNCTIONS (verbatim from STRAIGHT_COPY_PASTE/L1_*.py,
# already individually tested there)
# ======================================================================
def additive_encrypt(plaintext, key):
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + key) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def additive_decrypt(ciphertext, key):
    return additive_encrypt(ciphertext, -key)


def multiplicative_encrypt(plaintext, key):
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base) * key % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def multiplicative_decrypt(ciphertext, key):
    key_inv = pow(key, -1, 26)
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base) * key_inv % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def affine_encrypt(plaintext, a, b):
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((a * (ord(ch) - base) + b) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def affine_decrypt(ciphertext, a, b):
    a_inv = pow(a, -1, 26)
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(a_inv * (ord(ch) - base - b) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def vigenere_encrypt(plaintext, key):
    key = key.upper()
    result, k = [], 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[k % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result, k = [], 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[k % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)


def autokey_encrypt(plaintext, seed_key):
    seed_key = seed_key.upper()
    running_key = seed_key + letters_only_upper(plaintext)
    result, k = [], 0
    for ch in plaintext:
        if ch.isalpha():
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
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(running_key[k]) - ord('A')
            plain_letter_upper = chr((ord(ch) - base - shift) % 26 + ord('A'))
            running_key.append(plain_letter_upper)
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)


def playfair_build_grid(key):
    key = "".join(ch for ch in key.upper() if ch.isalpha()).replace("J", "I")
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    grid = [seen[i * 5:(i + 1) * 5] for i in range(5)]
    pos = {ch: (r, c) for r, row in enumerate(grid) for c, ch in enumerate(row)}
    return grid, pos


def playfair_prepare_digraphs(plaintext):
    letters = "".join(ch for ch in plaintext.upper() if ch.isalpha()).replace("J", "I")
    i, digraphs = 0, []
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else "X"
        if a == b:
            digraphs.append(a + "X")
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    if digraphs and len(digraphs[-1]) == 1:
        digraphs[-1] += "X"
    return digraphs


def playfair_encrypt(plaintext, key):
    grid, pos = playfair_build_grid(key)
    out = []
    for a, b in playfair_prepare_digraphs(plaintext):
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(grid[ra][(ca + 1) % 5] + grid[rb][(cb + 1) % 5])
        elif ca == cb:
            out.append(grid[(ra + 1) % 5][ca] + grid[(rb + 1) % 5][cb])
        else:
            out.append(grid[ra][cb] + grid[rb][ca])
    return "".join(out)


def playfair_decrypt(ciphertext, key):
    grid, pos = playfair_build_grid(key)
    out = []
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(grid[ra][(ca - 1) % 5] + grid[rb][(cb - 1) % 5])
        elif ca == cb:
            out.append(grid[(ra - 1) % 5][ca] + grid[(rb - 1) % 5][cb])
        else:
            out.append(grid[ra][cb] + grid[rb][ca])
    return "".join(out)


def hill_mat_inverse_2x2(matrix, modulus=26):
    a, b = matrix[0]
    c, d = matrix[1]
    det = (a * d - b * c) % modulus
    det_inv = pow(det, -1, modulus)
    return [
        [(d * det_inv) % modulus, (-b * det_inv) % modulus],
        [(-c * det_inv) % modulus, (a * det_inv) % modulus],
    ]


def hill_prepare(plaintext):
    letters = "".join(ch for ch in plaintext.upper() if ch.isalpha())
    if len(letters) % 2 != 0:
        letters += "X"
    return letters


def hill_encrypt(plaintext, key_matrix):
    letters = hill_prepare(plaintext)
    out = []
    for i in range(0, len(letters), 2):
        p1, p2 = ord(letters[i]) - ord('A'), ord(letters[i + 1]) - ord('A')
        c1 = (key_matrix[0][0] * p1 + key_matrix[0][1] * p2) % 26
        c2 = (key_matrix[1][0] * p1 + key_matrix[1][1] * p2) % 26
        out.append(chr(c1 + ord('A')))
        out.append(chr(c2 + ord('A')))
    return "".join(out)


def hill_decrypt(ciphertext, key_matrix):
    inv = hill_mat_inverse_2x2(key_matrix)
    out = []
    for i in range(0, len(ciphertext), 2):
        c1, c2 = ord(ciphertext[i]) - ord('A'), ord(ciphertext[i + 1]) - ord('A')
        p1 = (inv[0][0] * c1 + inv[0][1] * c2) % 26
        p2 = (inv[1][0] * c1 + inv[1][1] * c2) % 26
        out.append(chr(p1 + ord('A')))
        out.append(chr(p2 + ord('A')))
    return "".join(out)


def transposition_key_order(key):
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def transposition_encrypt(plaintext, key):
    cols = len(key)
    padded = plaintext + "X" * (-len(plaintext) % cols)
    rows = [padded[i:i + cols] for i in range(0, len(padded), cols)]
    order = transposition_key_order(key)
    return "".join("".join(row[c] for row in rows) for c in order)


def transposition_decrypt(ciphertext, key):
    cols = len(key)
    rows_count = len(ciphertext) // cols
    order = transposition_key_order(key)
    col_texts = [ciphertext[i * rows_count:(i + 1) * rows_count] for i in range(cols)]
    columns = [None] * cols
    for i, original_col in enumerate(order):
        columns[original_col] = col_texts[i]
    rows = ["".join(columns[c][r] for c in range(cols)) for r in range(rows_count)]
    return "".join(rows).rstrip("X")


# ======================================================================
# CONFIDENTIALITY BACKENDS
# Each backend: generate_keys(), encrypt(plaintext_str, keys)->ct,
# decrypt(ct, keys)->plaintext_str (CANONICAL form - for classical ciphers
# this may be uppercase/padded, never the raw pre-encryption input - same
# "hash what decrypt() actually returns" rule as ROLE_LOGIN_SYSTEMS),
# ct_to_bytes(ct)->bytes, keys_hex(keys)->list of (label, hexstr).
# ======================================================================
CONFIDENTIALITY_BACKENDS = {}


def _register_conf(name, generate_keys, encrypt, decrypt, ct_to_bytes, keys_hex):
    CONFIDENTIALITY_BACKENDS[name] = {
        "generate_keys": generate_keys, "encrypt": encrypt, "decrypt": decrypt,
        "ct_to_bytes": ct_to_bytes, "keys_hex": keys_hex,
    }


# ---- classical ciphers: key material is a small int/str/matrix, same for
# both "sides" (no public/private split) ----
def _classical_ct_to_bytes(ct):
    return ct.encode()


_register_conf("ADDITIVE",
    lambda: {"key": random.randint(1, 25)},
    lambda pt, k: additive_encrypt(pt, k["key"]),
    lambda ct, k: additive_decrypt(ct, k["key"]),
    _classical_ct_to_bytes,
    lambda k: [("key", format(k["key"], "x"))])

_register_conf("MULTIPLICATIVE",
    lambda: {"key": random.choice([3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25])},
    lambda pt, k: multiplicative_encrypt(pt, k["key"]),
    lambda ct, k: multiplicative_decrypt(ct, k["key"]),
    _classical_ct_to_bytes,
    lambda k: [("key", format(k["key"], "x"))])

_register_conf("AFFINE",
    lambda: {"a": random.choice([3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]), "b": random.randint(1, 25)},
    lambda pt, k: affine_encrypt(pt, k["a"], k["b"]),
    lambda ct, k: affine_decrypt(ct, k["a"], k["b"]),
    _classical_ct_to_bytes,
    lambda k: [("a", format(k["a"], "x")), ("b", format(k["b"], "x"))])

_register_conf("VIGENERE",
    lambda: {"key": "SECURE"},
    lambda pt, k: vigenere_encrypt(pt, k["key"]),
    lambda ct, k: vigenere_decrypt(ct, k["key"]),
    _classical_ct_to_bytes,
    lambda k: [("key", k["key"].encode().hex())])

_register_conf("AUTOKEY",
    lambda: {"key": "KEY"},
    lambda pt, k: autokey_encrypt(pt, k["key"]),
    lambda ct, k: autokey_decrypt(ct, k["key"]),
    _classical_ct_to_bytes,
    lambda k: [("seed_key", k["key"].encode().hex())])

_register_conf("PLAYFAIR",
    lambda: {"key": "MONARCHY"},
    lambda pt, k: playfair_encrypt(pt, k["key"]),
    lambda ct, k: playfair_decrypt(ct, k["key"]),
    _classical_ct_to_bytes,
    lambda k: [("key", k["key"].encode().hex())])

_register_conf("HILL",
    lambda: {"matrix": [[3, 3], [2, 7]]},
    lambda pt, k: hill_encrypt(pt, k["matrix"]),
    lambda ct, k: hill_decrypt(ct, k["matrix"]),
    _classical_ct_to_bytes,
    lambda k: [("matrix", json.dumps(k["matrix"]).encode().hex())])

_register_conf("TRANSPOSITION",
    lambda: {"key": "ZEBRA"},
    lambda pt, k: transposition_encrypt(pt, k["key"]),
    lambda ct, k: transposition_decrypt(ct, k["key"]),
    _classical_ct_to_bytes,
    lambda k: [("key", k["key"].encode().hex())])




# ---- modern symmetric ciphers: DES / AES-128/192/256 / 3DES, all CBC mode
# (established kit default), key material = {"key": bytes} ----
def _sym_ct_to_bytes(ct):
    return ct["iv"] + ct["ciphertext"]


def _sym_keys_hex(k):
    return [("key", k["key"].hex())]


def _make_block_cipher_backend(module, key_bytes, block_size_attr="block_size"):
    def genkeys():
        return {"key": os.urandom(key_bytes)}

    def enc(pt, k):
        cipher = module.new(k["key"], module.MODE_CBC)
        iv = cipher.iv
        ct = cipher.encrypt(pad(pt.encode(), module.block_size))
        return {"iv": iv, "ciphertext": ct}

    def dec(ct, k):
        cipher = module.new(k["key"], module.MODE_CBC, iv=ct["iv"])
        return unpad(cipher.decrypt(ct["ciphertext"]), module.block_size).decode()

    return genkeys, enc, dec


_g, _e, _d = _make_block_cipher_backend(DES, 8)
_register_conf("DES", _g, _e, _d, _sym_ct_to_bytes, _sym_keys_hex)

_g, _e, _d = _make_block_cipher_backend(AES, 16)
_register_conf("AES128", _g, _e, _d, _sym_ct_to_bytes, _sym_keys_hex)

_g, _e, _d = _make_block_cipher_backend(AES, 24)
_register_conf("AES192", _g, _e, _d, _sym_ct_to_bytes, _sym_keys_hex)

_g, _e, _d = _make_block_cipher_backend(AES, 32)
_register_conf("AES256", _g, _e, _d, _sym_ct_to_bytes, _sym_keys_hex)


def _des3_genkeys():
    while True:
        key = DES3.adjust_key_parity(os.urandom(24))
        try:
            DES3.new(key, DES3.MODE_ECB)
            return {"key": key}
        except ValueError:
            continue  # degenerate (two-key-equivalent) key, regenerate


def _des3_enc(pt, k):
    cipher = DES3.new(k["key"], DES3.MODE_CBC)
    iv = cipher.iv
    ct = cipher.encrypt(pad(pt.encode(), DES3.block_size))
    return {"iv": iv, "ciphertext": ct}


def _des3_dec(ct, k):
    cipher = DES3.new(k["key"], DES3.MODE_CBC, iv=ct["iv"])
    return unpad(cipher.decrypt(ct["ciphertext"]), DES3.block_size).decode()


_register_conf("3DES", _des3_genkeys, _des3_enc, _des3_dec, _sym_ct_to_bytes, _sym_keys_hex)



# ---- asymmetric confidentiality: RSA, ElGamal, ECC/ECIES hybrid, Rabin,
# Paillier. keys = {"public": ..., "private": ...}; encrypt uses "public",
# decrypt uses "private" (both passed in the same keys dict - matches how
# every BIG_SYSTEMS file in this kit already keeps both parts reachable
# centrally for a classroom demo) ----
def _rsa_conf_genkeys():
    key = RSA.generate(2048)
    return {"public": key.publickey(), "private": key}


def _rsa_conf_enc(pt, k):
    pub = k["public"]
    return [pow(b, pub.e, pub.n) for b in pt.encode()]


def _rsa_conf_dec(ct, k):
    priv = k["private"]
    return bytes(pow(c, priv.d, priv.n) for c in ct).decode()


def _rsa_conf_ct_to_bytes(ct):
    return json.dumps(ct).encode()


def _rsa_conf_keys_hex(k):
    return [("n", format(k["public"].n, "x")), ("e", format(k["public"].e, "x")),
            ("d", format(k["private"].d, "x"))]


_register_conf("RSA", _rsa_conf_genkeys, _rsa_conf_enc, _rsa_conf_dec,
                _rsa_conf_ct_to_bytes, _rsa_conf_keys_hex)


def _elgamal_conf_genkeys():
    p = gen_prime(256)
    g = 2
    x = random.randrange(2, p - 2)
    y = pow(g, x, p)
    return {"public": (p, g, y), "private": x}


def _elgamal_conf_enc(pt, k):
    p, g, y = k["public"]
    pairs = []
    for b in pt.encode():
        r = random.randrange(2, p - 2)
        c1 = pow(g, r, p)
        c2 = (b * pow(y, r, p)) % p
        pairs.append((c1, c2))
    return pairs


def _elgamal_conf_dec(ct, k):
    p, g, y = k["public"]
    x = k["private"]
    out = bytearray()
    for c1, c2 in ct:
        s = pow(c1, x, p)
        m = (c2 * pow(s, -1, p)) % p
        out.append(m)
    return bytes(out).decode()


def _elgamal_conf_ct_to_bytes(ct):
    return json.dumps(ct).encode()


def _elgamal_conf_keys_hex(k):
    p, g, y = k["public"]
    return [("p", format(p, "x")), ("g", format(g, "x")), ("y", format(y, "x")),
            ("x", format(k["private"], "x"))]


_register_conf("ELGAMAL", _elgamal_conf_genkeys, _elgamal_conf_enc, _elgamal_conf_dec,
                _elgamal_conf_ct_to_bytes, _elgamal_conf_keys_hex)

CURVE = ec.SECP256R1()


def _ecc_conf_genkeys():
    priv = ec.generate_private_key(CURVE)
    return {"public": priv.public_key(), "private": priv}


def _ecc_conf_enc(pt, k):
    ephemeral_private = ec.generate_private_key(CURVE)
    shared_secret = ephemeral_private.exchange(ec.ECDH(), k["public"])
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"ecc-ecies-demo").derive(shared_secret)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, pt.encode(), None)
    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint)
    return {"ciphertext": ciphertext, "nonce": nonce, "ephemeral_public": ephemeral_public_bytes}


def _ecc_conf_dec(ct, k):
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        CURVE, ct["ephemeral_public"])
    shared_secret = k["private"].exchange(ec.ECDH(), ephemeral_public)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"ecc-ecies-demo").derive(shared_secret)
    return AESGCM(aes_key).decrypt(ct["nonce"], ct["ciphertext"], None).decode()


def _ecc_conf_ct_to_bytes(ct):
    return ct["ephemeral_public"] + ct["nonce"] + ct["ciphertext"]


def _ecc_conf_keys_hex(k):
    nums = k["public"].public_numbers()
    priv_val = k["private"].private_numbers().private_value
    return [("x", format(nums.x, "x")), ("y", format(nums.y, "x")), ("d", format(priv_val, "x"))]


_register_conf("ECC", _ecc_conf_genkeys, _ecc_conf_enc, _ecc_conf_dec,
                _ecc_conf_ct_to_bytes, _ecc_conf_keys_hex)


def _rabin_conf_genkeys():
    p = gen_blum_prime(256)
    q = gen_blum_prime(256)
    n = p * q
    return {"public": n, "private": (p, q)}


def _rabin_conf_enc(pt, k):
    n = k["public"]
    return [pow(b, 2, n) for b in pt.encode()]


def _rabin_conf_dec(ct, k):
    p, q = k["private"]
    n = p * q
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    out = bytearray()
    for c in ct:
        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)
        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3
        for cand in (r1, r2, r3, r4):
            if 0 <= cand < 256:
                out.append(cand)
                break
        else:
            out.append(r1 % 256)
    return bytes(out).decode(errors="replace")


def _rabin_conf_ct_to_bytes(ct):
    return json.dumps(ct).encode()


def _rabin_conf_keys_hex(k):
    return [("n", format(k["public"], "x")), ("p", format(k["private"][0], "x")),
            ("q", format(k["private"][1], "x"))]


_register_conf("RABIN", _rabin_conf_genkeys, _rabin_conf_enc, _rabin_conf_dec,
                _rabin_conf_ct_to_bytes, _rabin_conf_keys_hex)


def _paillier_lcm(a, b):
    return a * b // math.gcd(a, b)


def _paillier_conf_genkeys():
    p = gen_prime(128)
    q = gen_prime(128)
    while p == q:
        q = gen_prime(128)
    n = p * q
    n_sq = n * n
    g = n + 1
    lam = _paillier_lcm(p - 1, q - 1)
    mu = pow(lam, -1, n)
    return {"public": (n, g), "private": (lam, mu)}


def _paillier_conf_enc(pt, k):
    n, g = k["public"]
    n_sq = n * n
    out = []
    for b in pt.encode():
        while True:
            r = random.randrange(1, n)
            if r % n != 0:
                break
        out.append((pow(g, b, n_sq) * pow(r, n, n_sq)) % n_sq)
    return out


def _paillier_conf_dec(ct, k):
    n, g = k["public"]
    lam, mu = k["private"]
    n_sq = n * n
    out = bytearray()
    for c in ct:
        x = pow(c, lam, n_sq)
        L = (x - 1) // n
        out.append((L * mu) % n)
    return bytes(out).decode()


def _paillier_conf_ct_to_bytes(ct):
    return json.dumps(ct).encode()


def _paillier_conf_keys_hex(k):
    return [("n", format(k["public"][0], "x")), ("g", format(k["public"][1], "x")),
            ("lambda", format(k["private"][0], "x")), ("mu", format(k["private"][1], "x"))]


_register_conf("PAILLIER", _paillier_conf_genkeys, _paillier_conf_enc, _paillier_conf_dec,
                _paillier_conf_ct_to_bytes, _paillier_conf_keys_hex)



# ======================================================================
# SIGNATURE BACKENDS
# generate_keys()->keys, sign(hash_bytes, keys)->sig (opaque),
# verify(hash_bytes, sig, keys)->bool, sig_hex(sig)->str
# ======================================================================
SIGNATURE_BACKENDS = {}


def _register_sig(name, generate_keys, sign, verify, sig_hex, keys_hex):
    SIGNATURE_BACKENDS[name] = {
        "generate_keys": generate_keys, "sign": sign, "verify": verify,
        "sig_hex": sig_hex, "keys_hex": keys_hex,
    }


def _rsa_sig_genkeys():
    key = RSA.generate(2048)
    return {"public": key.publickey(), "private": key}


def _rsa_sig_sign(h, k):
    return pkcs1_15.new(k["private"]).sign(PC_SHA256.new(h))


def _rsa_sig_verify(h, sig, k):
    try:
        pkcs1_15.new(k["public"]).verify(PC_SHA256.new(h), sig)
        return True
    except (ValueError, TypeError):
        return False


_register_sig("RSA", _rsa_sig_genkeys, _rsa_sig_sign, _rsa_sig_verify,
               lambda s: s.hex(),
               lambda k: [("n", format(k["public"].n, "x")), ("e", format(k["public"].e, "x"))])


def _elgamal_sig_genkeys():
    p = gen_prime(256)
    g = 2
    x = random.randrange(2, p - 2)
    y = pow(g, x, p)
    return {"public": (p, g, y), "private": x}


def _elgamal_sig_hash_int(h, modulus):
    return int.from_bytes(hashlib.sha256(h).digest(), "big") % modulus


def _elgamal_sig_sign(h, k):
    p, g, y = k["public"]
    x = k["private"]
    while True:
        kk = random.randrange(2, p - 2)
        if math.gcd(kk, p - 1) == 1:
            break
    hh = _elgamal_sig_hash_int(h, p - 1)
    r = pow(g, kk, p)
    kk_inv = pow(kk, -1, p - 1)
    s = (kk_inv * (hh - x * r)) % (p - 1)
    return (r, s)


def _elgamal_sig_verify(h, sig, k):
    p, g, y = k["public"]
    r, s = sig
    if not (0 < r < p):
        return False
    hh = _elgamal_sig_hash_int(h, p - 1)
    lhs = (pow(y, r, p) * pow(r, s, p)) % p
    rhs = pow(g, hh, p)
    return lhs == rhs


_register_sig("ELGAMAL", _elgamal_sig_genkeys, _elgamal_sig_sign, _elgamal_sig_verify,
               lambda s: f"(r={format(s[0],'x')}, s={format(s[1],'x')})",
               lambda k: [("p", format(k["public"][0], "x")), ("y", format(k["public"][2], "x"))])

_SCHNORR_P = 7919
_SCHNORR_Q = 107
_SCHNORR_G = pow(2, (_SCHNORR_P - 1) // _SCHNORR_Q, _SCHNORR_P)


def _schnorr_sig_genkeys():
    x = random.randint(2, _SCHNORR_Q - 1)
    y = pow(_SCHNORR_G, -x, _SCHNORR_P)
    return {"public": y, "private": x}


def _schnorr_sig_sign(h, k):
    x = k["private"]
    kk = random.randint(2, _SCHNORR_Q - 1)
    r = pow(_SCHNORR_G, kk, _SCHNORR_P)
    e = int.from_bytes(hashlib.sha256(r.to_bytes(32, "big") + h).digest(), "big") % _SCHNORR_Q
    s = (kk + x * e) % _SCHNORR_Q
    return (e, s)


def _schnorr_sig_verify(h, sig, k):
    e, s = sig
    y = k["public"]
    r_v = (pow(_SCHNORR_G, s, _SCHNORR_P) * pow(y, e, _SCHNORR_P)) % _SCHNORR_P
    e_v = int.from_bytes(hashlib.sha256(r_v.to_bytes(32, "big") + h).digest(), "big") % _SCHNORR_Q
    return e_v == e


_register_sig("SCHNORR", _schnorr_sig_genkeys, _schnorr_sig_sign, _schnorr_sig_verify,
               lambda s: f"(e={format(s[0],'x')}, s={format(s[1],'x')})",
               lambda k: [("y", format(k["public"], "x"))])


def _ecdsa_sig_genkeys():
    priv = ec.generate_private_key(CURVE)
    return {"public": priv.public_key(), "private": priv}


def _ecdsa_sig_sign(h, k):
    return k["private"].sign(h, ec.ECDSA(hashes.SHA256()))


def _ecdsa_sig_verify(h, sig, k):
    try:
        k["public"].verify(sig, h, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


_register_sig("ECDSA", _ecdsa_sig_genkeys, _ecdsa_sig_sign, _ecdsa_sig_verify,
               lambda s: s.hex(),
               lambda k: [("x", format(k["public"].public_numbers().x, "x"))])


def _rabin_sig_genkeys():
    p = gen_blum_prime(256)
    q = gen_blum_prime(256)
    n = p * q
    return {"public": n, "private": (p, q)}


def _rabin_sig_hash_to_int(h, counter, n):
    hh = hashlib.sha256(h + counter.to_bytes(4, "big")).digest()
    return int.from_bytes(hh, "big") % n


def _rabin_sig_is_qr(c, p, q):
    return pow(c, (p - 1) // 2, p) == 1 and pow(c, (q - 1) // 2, q) == 1


def _rabin_sig_sqrt_mod_n(c, p, q):
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    return (yp * p * mq + yq * q * mp) % n


def _rabin_sig_sign(h, k):
    p, q = k["private"]
    n = k["public"]
    counter = 0
    while True:
        hh = _rabin_sig_hash_to_int(h, counter, n)
        if _rabin_sig_is_qr(hh, p, q):
            return (_rabin_sig_sqrt_mod_n(hh, p, q), counter)
        counter += 1


def _rabin_sig_verify(h, sig, k):
    root, counter = sig
    n = k["public"]
    expected = _rabin_sig_hash_to_int(h, counter, n)
    return pow(root, 2, n) == expected


_register_sig("RABIN", _rabin_sig_genkeys, _rabin_sig_sign, _rabin_sig_verify,
               lambda s: f"(root={format(s[0],'x')}, counter={s[1]})",
               lambda k: [("n", format(k["public"], "x"))])


def _none_sig_genkeys():
    return {}


SIGNATURE_BACKENDS["NONE"] = {
    "generate_keys": _none_sig_genkeys,
    "sign": lambda h, k: None,
    "verify": lambda h, sig, k: True,
    "sig_hex": lambda s: "(no signature scheme selected)",
    "keys_hex": lambda k: [],
}



# ======================================================================
# HASH BACKENDS - hash(data: bytes) -> bytes
# ======================================================================
def _custom_djb2_hash(data: bytes) -> bytes:
    h = 5381
    for b in data:
        h = ((h * 33) + b) & 0xFFFFFFFFFFFFFFFF   # 64-bit djb2 variant
    return h.to_bytes(8, "big")


HASH_BACKENDS = {
    "SHA256": lambda data: hashlib.sha256(data).digest(),
    "SHA1": lambda data: hashlib.sha1(data).digest(),
    "SHA512": lambda data: hashlib.sha512(data).digest(),
    "MD5": lambda data: hashlib.md5(data).digest(),
    "CUSTOM": _custom_djb2_hash,
}



# ======================================================================
# OPTIONAL EXTENSION 1: KEY EXCHANGE (derives a symmetric key instead of
# generating one randomly - only meaningful when CONFIDENTIALITY_ALGO is
# a symmetric one: DES/AES128/AES192/AES256/3DES)
# ======================================================================
def dh_derive_shared_key(key_bytes_needed=32):
    """Diffie-Hellman key exchange -> SHA-256-derived shared key.
    Returns (shared_key_bytes, info_dict_for_display)."""
    p = gen_prime(256)
    g = 2
    a_private = random.randrange(2, p - 2)
    b_private = random.randrange(2, p - 2)
    a_public = pow(g, a_private, p)
    b_public = pow(g, b_private, p)
    a_shared = pow(b_public, a_private, p)
    b_shared = pow(a_public, b_private, p)
    assert a_shared == b_shared
    key = hashlib.sha256(str(a_shared).encode()).digest()[:key_bytes_needed]
    return key, {"p": p, "g": g, "A_public": a_public, "B_public": b_public, "shared_int": a_shared}


def ecdh_derive_shared_key(key_bytes_needed=32):
    """ECDH key exchange -> HKDF-derived shared key."""
    a_private = ec.generate_private_key(CURVE)
    b_private = ec.generate_private_key(CURVE)
    a_shared_raw = a_private.exchange(ec.ECDH(), b_private.public_key())
    b_shared_raw = b_private.exchange(ec.ECDH(), a_private.public_key())
    assert a_shared_raw == b_shared_raw
    key = HKDF(algorithm=hashes.SHA256(), length=key_bytes_needed, salt=None,
               info=b"universal-template-ecdh").derive(a_shared_raw)
    a_pub_bytes = a_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    b_pub_bytes = b_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return key, {"A_public": a_pub_bytes.hex(), "B_public": b_pub_bytes.hex()}


KEY_EXCHANGE_BACKENDS = {"DH": dh_derive_shared_key, "ECDH": ecdh_derive_shared_key}



# ======================================================================
# OPTIONAL EXTENSION 2: HOMOMORPHIC COMBINE (only meaningful when
# CONFIDENTIALITY_ALGO is PAILLIER (additive) or ELGAMAL/RSA
# (multiplicative) - combines two ENCRYPTED INTEGERS without decrypting
# either one first)
# ======================================================================
def homomorphic_combine(algo, ct1, ct2, keys):
    """ct1, ct2 are single ciphertext integers (not the per-byte list form
    used by the main confidentiality backends - this works on one number,
    e.g. a vote or a score, matching Lab7_PHE's convention)."""
    if algo == "PAILLIER":
        n, g = keys["public"]
        return (ct1 * ct2) % (n * n)          # -> Enc(m1 + m2)
    elif algo == "ELGAMAL":
        p, g, y = keys["public"]
        a1, b1 = ct1
        a2, b2 = ct2
        return (a1 * a2) % p, (b1 * b2) % p    # -> Enc(m1 * m2 mod p)
    elif algo == "RSA":
        n = keys["public"].n
        return (ct1 * ct2) % n                 # -> Enc(m1 * m2 mod n)  (raw RSA only)
    else:
        raise ValueError(f"Homomorphic combine not defined for {algo} - only "
                          f"PAILLIER (addition), ELGAMAL/RSA (multiplication).")


def homomorphic_encrypt_int(algo, value, keys):
    """Encrypts a single integer (not text) - for the homomorphic demo action."""
    if algo == "PAILLIER":
        n, g = keys["public"]
        n_sq = n * n
        while True:
            r = random.randrange(1, n)
            if r % n != 0:
                break
        return (pow(g, value, n_sq) * pow(r, n, n_sq)) % n_sq
    elif algo == "ELGAMAL":
        p, g, y = keys["public"]
        r = random.randrange(2, p - 2)
        return pow(g, r, p), (value * pow(y, r, p)) % p
    elif algo == "RSA":
        pub = keys["public"]
        return pow(value, pub.e, pub.n)
    else:
        raise ValueError(f"Homomorphic encrypt not defined for {algo}")


def homomorphic_decrypt_int(algo, ct, keys):
    if algo == "PAILLIER":
        n, g = keys["public"]
        lam, mu = keys["private"]
        n_sq = n * n
        x = pow(ct, lam, n_sq)
        L = (x - 1) // n
        return (L * mu) % n
    elif algo == "ELGAMAL":
        p, g, y = keys["public"]
        x = keys["private"]
        a, b = ct
        s = pow(a, x, p)
        return (b * pow(s, -1, p)) % p
    elif algo == "RSA":
        priv = keys["private"]
        return pow(ct, priv.d, priv.n)
    else:
        raise ValueError(f"Homomorphic decrypt not defined for {algo}")


def homomorphic_ct_hex(v):
    """Hex-format a homomorphic ciphertext for display. PAILLIER/RSA give a
    plain int; ELGAMAL gives an (a, b) tuple - format each half separately
    so the hex rule still holds for this extension's ciphertexts."""
    if isinstance(v, tuple):
        return "(" + ", ".join(format(part, "x") for part in v) + ")"
    return format(v, "x")


# ======================================================================
# OPTIONAL EXTENSION 3: SEARCHABLE INDEX (works regardless of which
# CONFIDENTIALITY_ALGO is active - deterministic HMAC token per keyword,
# same fix as STRAIGHT_COPY_PASTE/Lab8_SearchableEncryption/*.py)
# ======================================================================
def make_index_key():
    return os.urandom(32)


def index_token(word, index_key):
    return hmac_lib.new(index_key, word.lower().encode(), hashlib.sha256).hexdigest()


def index_add_record(index, record_id, text, index_key):
    for word in set(text.split()):
        index.setdefault(index_token(word, index_key), set()).add(record_id)


def index_search(index, query_word, index_key):
    return index.get(index_token(query_word, index_key), set())




# ======================================================================
# OPTIONAL EXTENSION 4: TIMESTAMP WINDOW CHECK
# ======================================================================
def timestamp_now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp_in_window(ts_str, window_minutes=60):
    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    delta = (datetime.now() - ts).total_seconds()
    return -60 <= delta <= window_minutes * 60




# ======================================================================
# OPTIONAL EXTENSION 5: THRESHOLD DECRYPTION (simplified n-of-n additive
# key-sharing of the Paillier private exponent - same simplification used
# in BIG_SYSTEMS/secureEVoting_*.py, documented there as NOT a rigorous
# distributed-key-generation threshold scheme, just a teaching-level demo)
# ======================================================================
def paillier_make_threshold_shares(lam, n, n_authorities=3):
    shares = [random.randrange(1, n * lam) for _ in range(n_authorities - 1)]
    last = (lam - sum(shares)) % (n * lam)
    shares.append(last)
    return shares


def paillier_threshold_decrypt(ct, shares, n):
    """Summing all n-of-n shares gives a value congruent to lambda modulo
    n*lambda (the order of the ciphertext group), so raising ct to this
    sum works identically to raising it to the real lambda - same trick
    already proven in BIG_SYSTEMS/secureEVoting_*.py."""
    reconstructed_lam = sum(shares)
    mu = pow(reconstructed_lam, -1, n)
    n_sq = n * n
    x = pow(ct, reconstructed_lam, n_sq)
    L = (x - 1) // n
    return (L * mu) % n




# ======================================================================
# CONFIG VALIDATION + SETUP
# ======================================================================
DEMO_RECORD_TEXT = "The Quick Brown Fox Jumps Over The Lazy Dog"

RECORDS = []
SIGN_KEYS = {}
CONF_KEYS = None
INDEX_KEY = None
INDEX = {}
RUNNING_TALLY = None
THRESHOLD_SHARES = None

_HOMOMORPHIC_ALGOS = ("PAILLIER", "ELGAMAL", "RSA")


def setup_system():
    global CONF_KEYS, INDEX_KEY, RUNNING_TALLY, THRESHOLD_SHARES
    global ENABLE_HOMOMORPHIC_DEMO, ENABLE_THRESHOLD_DECRYPT

    if CONFIDENTIALITY_ALGO not in CONFIDENTIALITY_BACKENDS:
        raise ValueError(f"Unknown CONFIDENTIALITY_ALGO '{CONFIDENTIALITY_ALGO}'. "
                          f"Valid options: {sorted(CONFIDENTIALITY_BACKENDS)}")
    if SIGNATURE_ALGO not in SIGNATURE_BACKENDS:
        raise ValueError(f"Unknown SIGNATURE_ALGO '{SIGNATURE_ALGO}'. "
                          f"Valid options: {sorted(SIGNATURE_BACKENDS)}")
    if HASH_ALGO not in HASH_BACKENDS:
        raise ValueError(f"Unknown HASH_ALGO '{HASH_ALGO}'. "
                          f"Valid options: {sorted(HASH_BACKENDS)}")

    if ENABLE_HOMOMORPHIC_DEMO and CONFIDENTIALITY_ALGO not in _HOMOMORPHIC_ALGOS:
        print(f"[CONFIG WARNING] ENABLE_HOMOMORPHIC_DEMO needs CONFIDENTIALITY_ALGO in "
              f"{_HOMOMORPHIC_ALGOS}, not '{CONFIDENTIALITY_ALGO}'. Disabling it.")
        ENABLE_HOMOMORPHIC_DEMO = False
    if ENABLE_THRESHOLD_DECRYPT and not (ENABLE_HOMOMORPHIC_DEMO and CONFIDENTIALITY_ALGO == "PAILLIER"):
        print("[CONFIG WARNING] ENABLE_THRESHOLD_DECRYPT needs ENABLE_HOMOMORPHIC_DEMO=True "
              "and CONFIDENTIALITY_ALGO='PAILLIER'. Disabling it.")
        ENABLE_THRESHOLD_DECRYPT = False

    print("[Setup] Generating confidentiality keys...")
    CONF_KEYS = CONFIDENTIALITY_BACKENDS[CONFIDENTIALITY_ALGO]["generate_keys"]()
    for label, hexval in CONFIDENTIALITY_BACKENDS[CONFIDENTIALITY_ALGO]["keys_hex"](CONF_KEYS):
        print(f"    {label} (hex): {hexval}")

    symmetric_algos = {"DES", "AES128", "AES192", "AES256", "3DES"}
    if ENABLE_KEY_EXCHANGE:
        if CONFIDENTIALITY_ALGO not in symmetric_algos:
            print(f"[CONFIG WARNING] ENABLE_KEY_EXCHANGE only makes sense for a symmetric "
                  f"CONFIDENTIALITY_ALGO ({sorted(symmetric_algos)}), not "
                  f"'{CONFIDENTIALITY_ALGO}'. Ignoring it.")
        else:
            needed_bytes = len(CONF_KEYS["key"])
            print(f"[Setup] Running {KEY_EXCHANGE_ALGO} key exchange between two parties...")
            derive = KEY_EXCHANGE_BACKENDS[KEY_EXCHANGE_ALGO]
            if CONFIDENTIALITY_ALGO == "3DES":
                while True:
                    derived_key, info = derive(needed_bytes)
                    try:
                        derived_key = DES3.adjust_key_parity(derived_key)
                        DES3.new(derived_key, DES3.MODE_ECB)
                        break
                    except ValueError:
                        continue  # degenerate 3DES key, re-derive
            else:
                derived_key, info = derive(needed_bytes)
            CONF_KEYS["key"] = derived_key
            print(f"    {KEY_EXCHANGE_ALGO} info: " +
                  ", ".join(f"{k}={format(v,'x') if isinstance(v,int) else v}" for k, v in info.items()))
            print(f"    Derived shared key (hex): {derived_key.hex()}")

    if ENABLE_SEARCHABLE_INDEX:
        INDEX_KEY = make_index_key()
        print(f"[Setup] Searchable index key (hex): {INDEX_KEY.hex()}")

    if ENABLE_HOMOMORPHIC_DEMO:
        identity_value = 0 if CONFIDENTIALITY_ALGO == "PAILLIER" else 1
        RUNNING_TALLY = homomorphic_encrypt_int(CONFIDENTIALITY_ALGO, identity_value, CONF_KEYS)
        print(f"[Setup] Homomorphic running tally initialised (encrypted identity value).")

    if ENABLE_THRESHOLD_DECRYPT:
        lam, mu = CONF_KEYS["private"]
        n, g = CONF_KEYS["public"]
        THRESHOLD_SHARES = paillier_make_threshold_shares(lam, n, THRESHOLD_AUTHORITIES)
        print(f"[Setup] {THRESHOLD_AUTHORITIES}-way threshold key shares generated:")
        for i, s in enumerate(THRESHOLD_SHARES):
            print(f"    Authority {i+1} share (hex): {format(s, 'x')}")


def get_or_create_sign_keys(username):
    if username not in SIGN_KEYS:
        SIGN_KEYS[username] = SIGNATURE_BACKENDS[SIGNATURE_ALGO]["generate_keys"]()
        print(f"[KeyGen] New {SIGNATURE_ALGO} signing keypair generated for '{username}'.")
        for label, hexval in SIGNATURE_BACKENDS[SIGNATURE_ALGO]["keys_hex"](SIGN_KEYS[username]):
            print(f"    {label} (hex): {hexval}")
    return SIGN_KEYS[username]


def pick_record(prompt="Enter Record ID: "):
    if not RECORDS:
        print("No records in the system yet.")
        return None
    for r in RECORDS:
        print(f"  {r['id']}  owner={r['owner']}  time={r.get('timestamp', 'n/a')}")
    rid = input(prompt).strip()
    for r in RECORDS:
        if r["id"] == rid:
            return r
    print("Record not found.")
    return None


# ======================================================================
# STUDENT ROLE
# ======================================================================
def student_menu(username):
    conf = CONFIDENTIALITY_BACKENDS[CONFIDENTIALITY_ALGO]
    hashfn = HASH_BACKENDS[HASH_ALGO]
    sign = SIGNATURE_BACKENDS[SIGNATURE_ALGO]

    while True:
        print(f"\n--- Student Menu ({username}) ---")
        print("1. Encrypt & Upload a record")
        if ENABLE_HOMOMORPHIC_DEMO:
            print("2. Submit a numeric value (homomorphically tallied, never decrypted here)")
        print("3. View my uploaded records")
        print("4. Logout")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            text = input("Enter record text (or press Enter for a demo record): ").strip()
            if not text:
                text = DEMO_RECORD_TEXT
            print(f"\n  Plaintext (hex): {text.encode().hex()}")

            ct = conf["encrypt"](text, CONF_KEYS)
            ct_bytes = conf["ct_to_bytes"](ct)
            print(f"  Ciphertext (hex): {ct_bytes.hex()}")

            cipher_hash = hashfn(ct_bytes)
            print(f"  {HASH_ALGO}(ciphertext) (hex): {cipher_hash.hex()}")

            signature = None
            if SIGNATURE_ALGO != "NONE":
                sign_keys = get_or_create_sign_keys(username)
                signature = sign["sign"](cipher_hash, sign_keys)
                print(f"  {SIGNATURE_ALGO} Signature (hex): {sign['sig_hex'](signature)}")

            # Hash what decrypt() actually returns (the CANONICAL round-tripped
            # text), never the raw pre-encryption input - classical ciphers in
            # particular can change the text on its round trip (Playfair's
            # null-letter insertion, Hill/Transposition padding). Same rule
            # already used throughout ROLE_LOGIN_SYSTEMS/*.py.
            canonical_plaintext = conf["decrypt"](ct, CONF_KEYS)
            integrity_hash = hashfn(canonical_plaintext.encode())
            print(f"  {HASH_ALGO}(plaintext) (hex): {integrity_hash.hex()}")

            timestamp = timestamp_now_str() if ENABLE_TIMESTAMP_CHECK else None
            if timestamp:
                print(f"  Timestamp: {timestamp}")

            record_id = f"REC{len(RECORDS) + 1:03d}"
            RECORDS.append({
                "id": record_id, "owner": username, "ct": ct,
                "cipher_hash": cipher_hash, "signature": signature,
                "integrity_hash": integrity_hash, "timestamp": timestamp,
            })

            if ENABLE_SEARCHABLE_INDEX:
                index_add_record(INDEX, record_id, canonical_plaintext, INDEX_KEY)
                print(f"  [Searchable index updated with this record's keywords]")

            print(f"\n[Upload Successful] Record ID: {record_id}")

        elif choice == "2" and ENABLE_HOMOMORPHIC_DEMO:
            global RUNNING_TALLY
            try:
                value = int(input("Enter an integer value to submit: ").strip())
            except ValueError:
                print("Please enter a valid integer.")
                continue
            ct_val = homomorphic_encrypt_int(CONFIDENTIALITY_ALGO, value, CONF_KEYS)
            print(f"  Encrypted value (hex): {homomorphic_ct_hex(ct_val)}")
            RUNNING_TALLY = homomorphic_combine(CONFIDENTIALITY_ALGO, RUNNING_TALLY, ct_val, CONF_KEYS)
            print(f"  Value combined into the running tally WITHOUT ever being decrypted.")
            print(f"  New running tally (still encrypted, hex): {homomorphic_ct_hex(RUNNING_TALLY)}")

        elif choice == "3":
            mine = [r for r in RECORDS if r["owner"] == username]
            if not mine:
                print("No records uploaded yet.")
            for r in mine:
                ct_bytes = conf["ct_to_bytes"](r["ct"])
                print(f"\nID: {r['id']}  |  Time: {r.get('timestamp', 'n/a')}")
                print(f"  Ciphertext (hex): {ct_bytes.hex()}")
                print(f"  Hash (hex):       {r['cipher_hash'].hex()}")
                if r["signature"] is not None:
                    print(f"  Signature (hex):  {sign['sig_hex'](r['signature'])}")

        elif choice == "4":
            break
        else:
            print("Invalid choice.")


# ======================================================================
# FACULTY ROLE
# ======================================================================
def faculty_menu(username):
    conf = CONFIDENTIALITY_BACKENDS[CONFIDENTIALITY_ALGO]
    hashfn = HASH_BACKENDS[HASH_ALGO]
    sign = SIGNATURE_BACKENDS[SIGNATURE_ALGO]

    while True:
        print(f"\n--- Faculty Menu ({username}) ---")
        print("1. Decrypt a record")
        print("2. Verify signature of a record")
        print("3. Compute & compare hash (integrity check)")
        if ENABLE_SEARCHABLE_INDEX:
            print("4. Search records by keyword")
        if ENABLE_TIMESTAMP_CHECK:
            print("5. Check a record's timestamp validity")
        if ENABLE_HOMOMORPHIC_DEMO and not ENABLE_THRESHOLD_DECRYPT:
            print("6. Decrypt the running homomorphic tally")
        if ENABLE_THRESHOLD_DECRYPT:
            print("7. Threshold-decrypt the running homomorphic tally")
        print("8. Logout")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            r = pick_record()
            if not r:
                continue
            ct_bytes = conf["ct_to_bytes"](r["ct"])
            print(f"\n  Ciphertext (hex): {ct_bytes.hex()}")
            plaintext = conf["decrypt"](r["ct"], CONF_KEYS)
            print(f"\n[Decrypted Record {r['id']}]")
            print(f"  Plaintext (hex): {plaintext.encode().hex()}")
            print(f"  Plaintext (text): {plaintext}")

        elif choice == "2":
            if SIGNATURE_ALGO == "NONE":
                print("No signature scheme is configured (SIGNATURE_ALGO = 'NONE').")
                continue
            r = pick_record()
            if not r:
                continue
            sign_keys = get_or_create_sign_keys(r["owner"])
            print(f"\n  {HASH_ALGO}(ciphertext) being checked (hex): {r['cipher_hash'].hex()}")
            print(f"  Signature under test (hex): {sign['sig_hex'](r['signature'])}")
            ok = sign["verify"](r["cipher_hash"], r["signature"], sign_keys)
            print(f"\n[Signature Verification] Record {r['id']} -> {'VALID' if ok else 'INVALID'}")

        elif choice == "3":
            r = pick_record()
            if not r:
                continue
            plaintext = conf["decrypt"](r["ct"], CONF_KEYS)
            recomputed = hashfn(plaintext.encode())
            print(f"  Decrypted plaintext (hex): {plaintext.encode().hex()}")
            print(f"  Stored integrity hash (hex):     {r['integrity_hash'].hex()}")
            print(f"  Recomputed hash (hex):           {recomputed.hex()}")
            match = recomputed == r["integrity_hash"]
            print(f"\n[Hash Comparison] Record {r['id']} -> {'MATCH' if match else 'MISMATCH'}")

        elif choice == "4" and ENABLE_SEARCHABLE_INDEX:
            query = input("Search term: ").strip()
            matches = index_search(INDEX, query, INDEX_KEY)
            print(f"Search token (hex): {index_token(query, INDEX_KEY)}")
            print(f"Matching record IDs (content never exposed to the search itself): {sorted(matches)}")

        elif choice == "5" and ENABLE_TIMESTAMP_CHECK:
            r = pick_record()
            if not r:
                continue
            ok = timestamp_in_window(r["timestamp"], TIMESTAMP_WINDOW_MINUTES)
            print(f"Record {r['id']} timestamp: {r['timestamp']}")
            print(f"Within {TIMESTAMP_WINDOW_MINUTES}-minute window: {ok}")

        elif choice == "6" and ENABLE_HOMOMORPHIC_DEMO and not ENABLE_THRESHOLD_DECRYPT:
            result = homomorphic_decrypt_int(CONFIDENTIALITY_ALGO, RUNNING_TALLY, CONF_KEYS)
            op = "sum" if CONFIDENTIALITY_ALGO == "PAILLIER" else "product"
            print(f"Running tally ciphertext (hex): {homomorphic_ct_hex(RUNNING_TALLY)}")
            print(f"Decrypted {op} of all submitted values: {result}")

        elif choice == "7" and ENABLE_THRESHOLD_DECRYPT:
            n, g = CONF_KEYS["public"]
            print(f"All {THRESHOLD_AUTHORITIES} authorities must supply their share "
                  f"(demo auto-supplies them; in reality each one types in their own):")
            for i, s in enumerate(THRESHOLD_SHARES):
                print(f"  Authority {i+1} share (hex): {format(s, 'x')}")
            result = paillier_threshold_decrypt(RUNNING_TALLY, THRESHOLD_SHARES, n)
            print(f"Threshold-decrypted sum of all submitted values: {result}")

        elif choice == "8":
            break
        else:
            print("Invalid choice.")


# ======================================================================
# HoD ROLE
# ======================================================================
def hod_menu(username):
    sign = SIGNATURE_BACKENDS[SIGNATURE_ALGO]

    while True:
        print(f"\n--- HoD Menu ({username}) ---")
        print("1. View hashed records (no plaintext, no ciphertext)")
        print("2. Verify signature (for accreditation)")
        print("3. Logout")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            if not RECORDS:
                print("No records in the system yet.")
            for r in RECORDS:
                print(f"\nID: {r['id']}  |  Owner: {r['owner']}  |  Time: {r.get('timestamp', 'n/a')}")
                print(f"  {HASH_ALGO}(ciphertext) (hex): {r['cipher_hash'].hex()}")
                print(f"  Integrity hash (hex):           {r['integrity_hash'].hex()}")
                if r["signature"] is not None:
                    print(f"  Signature (hex): {sign['sig_hex'](r['signature'])}")

        elif choice == "2":
            if SIGNATURE_ALGO == "NONE":
                print("No signature scheme is configured (SIGNATURE_ALGO = 'NONE').")
                continue
            r = pick_record()
            if not r:
                continue
            sign_keys = get_or_create_sign_keys(r["owner"])
            print(f"\n  {HASH_ALGO}(ciphertext) being checked (hex): {r['cipher_hash'].hex()}")
            print(f"  Signature under test (hex): {sign['sig_hex'](r['signature'])}")
            ok = sign["verify"](r["cipher_hash"], r["signature"], sign_keys)
            print(f"\n[Accreditation Signature Check] Record {r['id']} -> {'VALID' if ok else 'INVALID'}")

        elif choice == "3":
            break
        else:
            print("Invalid choice.")


# ======================================================================
# MAIN / ACCESS CONTROL
# ======================================================================
def main():
    print("====================================================")
    print(" UNIVERSAL EXAM TEMPLATE")
    print(f" Confidentiality: {CONFIDENTIALITY_ALGO}  |  Signature: {SIGNATURE_ALGO}  |  Hash: {HASH_ALGO}")
    extras = []
    if ENABLE_KEY_EXCHANGE:
        extras.append(f"Key exchange ({KEY_EXCHANGE_ALGO})")
    if ENABLE_SEARCHABLE_INDEX:
        extras.append("Searchable index")
    if ENABLE_TIMESTAMP_CHECK:
        extras.append("Timestamp check")
    if ENABLE_HOMOMORPHIC_DEMO:
        extras.append("Homomorphic tally")
    if ENABLE_THRESHOLD_DECRYPT:
        extras.append("Threshold decryption")
    if extras:
        print(" Extras: " + ", ".join(extras))
    print("====================================================")

    setup_system()

    while True:
        print("\n=== Login ===")
        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")
        role = input("Select role (1-4): ").strip()

        if role == "1":
            uname = input("Enter your username: ").strip() or "student1"
            student_menu(uname)
        elif role == "2":
            uname = input("Enter your username: ").strip() or "faculty1"
            faculty_menu(uname)
        elif role == "3":
            uname = input("Enter your username: ").strip() or "hod1"
            hod_menu(uname)
        elif role == "4":
            print("Exiting. Goodbye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
