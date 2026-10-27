"""Independent enhanced crypto lab generator.
Based on generate_solution.py; the original is unchanged.
Custom entities, per-action permissions, timestamps and timings; no classical ciphers.
Run: python generate_solution_with_entities.py
"""
from pathlib import Path
from datetime import datetime
import ast
import json
import re
import builtins

TEMPLATES = {'symmetric': {'AES-128': 'BLOCK_CIPHER, KEY_BYTES = AES, 16',
               'AES-192': 'BLOCK_CIPHER, KEY_BYTES = AES, 24',
               'AES-256': 'BLOCK_CIPHER, KEY_BYTES = AES, 32',
               'DES': 'BLOCK_CIPHER, KEY_BYTES = DES, 8',
               'Triple-DES': 'BLOCK_CIPHER, KEY_BYTES = DES3, 24'},
 'asymmetric': {'RSA': {'constants': '',
                        'code': 'def b64(data):\n'
                                '    return base64.b64encode(data).decode("ascii")\n'
                                '\n'
                                'def unb64(data):\n'
                                '    return base64.b64decode(data)\n'
                                '\n'
                                'def wrap_key(key):\n'
                                '    return '
                                'b64(PKCS1_OAEP.new(SERVER_RSA.publickey()).encrypt(key))\n'
                                '\n'
                                'def unwrap_key(wrapped):\n'
                                '    return PKCS1_OAEP.new(SERVER_RSA).decrypt(unb64(wrapped))'},
                'ElGamal': {'constants': 'P, G = 467, 2',
                            'code': 'def b64(data):\n'
                                    '    return base64.b64encode(data).decode("ascii")\n'
                                    '\n'
                                    'def unb64(data):\n'
                                    '    return base64.b64decode(data)\n'
                                    '\n'
                                    'def wrap_key(key):\n'
                                    '    pairs = []\n'
                                    '    for byte in key:\n'
                                    '        k = secrets.randbelow(P - 3) + 2\n'
                                    '        pairs.append([pow(G, k, P), (byte + 1) * '
                                    'pow(PUBLIC_Y, k, P) % P])\n'
                                    '    return pairs\n'
                                    '\n'
                                    'def unwrap_key(wrapped):\n'
                                    '    return bytes((b * pow(pow(a, PRIVATE_X, P), -1, P) % P) - '
                                    '1\n'
                                    '                 for a, b in wrapped)'},
                'ECDH': {'constants': '',
                         'code': 'def b64(data):\n'
                                 '    return base64.b64encode(data).decode("ascii")\n'
                                 '\n'
                                 'def unb64(data):\n'
                                 '    return base64.b64decode(data)\n'
                                 '\n'
                                 'def wrap_key(key):\n'
                                 '    # ECC hybrid encryption: ephemeral ECDH -> SHA256 -> AES key '
                                 'wrapping.\n'
                                 '    ephemeral = ECC.generate(curve="P-256")\n'
                                 '    point = SERVER_ECC.pointQ * ephemeral.d\n'
                                 '    shared_key = hashlib.sha256(int(point.x).to_bytes(32, '
                                 '"big")).digest()\n'
                                 '    cipher = AES.new(shared_key, AES.MODE_EAX)\n'
                                 '    ciphertext, tag = cipher.encrypt_and_digest(key)\n'
                                 '    return [ephemeral.public_key().export_key(format="PEM"),\n'
                                 '            b64(cipher.nonce), b64(ciphertext), b64(tag)]\n'
                                 '\n'
                                 'def unwrap_key(wrapped):\n'
                                 '    public_pem, nonce, ciphertext, tag = wrapped\n'
                                 '    point = ECC.import_key(public_pem).pointQ * SERVER_ECC.d\n'
                                 '    shared_key = hashlib.sha256(int(point.x).to_bytes(32, '
                                 '"big")).digest()\n'
                                 '    cipher = AES.new(shared_key, AES.MODE_EAX, '
                                 'nonce=unb64(nonce))\n'
                                 '    return cipher.decrypt_and_verify(unb64(ciphertext), '
                                 'unb64(tag))'},
                'DH': {'constants': 'P, G = 467, 2',
                       'code': 'def b64(data):\n'
                               '    return base64.b64encode(data).decode("ascii")\n'
                               '\n'
                               'def unb64(data):\n'
                               '    return base64.b64decode(data)\n'
                               '\n'
                               'def wrap_key(key):\n'
                               '    ephemeral = secrets.randbelow(P - 3) + 2\n'
                               '    public = pow(G, ephemeral, P)\n'
                               '    shared = pow(PUBLIC_Y, ephemeral, P)\n'
                               '    shared_key = hashlib.sha256(str(shared).encode()).digest()\n'
                               '    cipher = AES.new(shared_key, AES.MODE_EAX)\n'
                               '    ciphertext, tag = cipher.encrypt_and_digest(key)\n'
                               '    return [public, b64(cipher.nonce), b64(ciphertext), b64(tag)]\n'
                               '\n'
                               'def unwrap_key(wrapped):\n'
                               '    public, nonce, ciphertext, tag = wrapped\n'
                               '    shared = pow(public, PRIVATE_X, P)\n'
                               '    shared_key = hashlib.sha256(str(shared).encode()).digest()\n'
                               '    cipher = AES.new(shared_key, AES.MODE_EAX, '
                               'nonce=unb64(nonce))\n'
                               '    return cipher.decrypt_and_verify(unb64(ciphertext), '
                               'unb64(tag))'}},
 'hash': {'SHA256': 'def digest_text(text):\n    return hashlib.sha256(text.encode()).hexdigest()',
          'SHA1': 'def digest_text(text):\n    return hashlib.sha1(text.encode()).hexdigest()',
          'MD5': 'def digest_text(text):\n    return hashlib.md5(text.encode()).hexdigest()',
          'CUSTOM32': 'def digest_text(text):\n'
                      '    value = 5381\n'
                      '    for byte in text.encode():\n'
                      '        value = ((value * 33) + byte) & 0xffffffff\n'
                      '    return f"{value:08x}"',
          'SHA512': 'def digest_text(text):\n    return hashlib.sha512(text.encode()).hexdigest()'},
 'signature': {'RSA': {'constants': '',
                       'code': 'def generate_keys():\n'
                               '    private_key = RSA.generate(2048)\n'
                               '    return private_key, '
                               'private_key.publickey().export_key().decode()\n'
                               '\n'
                               '\n'
                               'def sign_message(message, private_key):\n'
                               '    signature = '
                               'pkcs1_15.new(private_key).sign(SHA256.new(message.encode()))\n'
                               '    return signature.hex(), digest_text(message)\n'
                               '\n'
                               '\n'
                               'def verify_signature(message, signature, public_key):\n'
                               '    try:\n'
                               '        '
                               'pkcs1_15.new(RSA.import_key(public_key)).verify(SHA256.new(message.encode()), '
                               'bytes.fromhex(signature))\n'
                               '        return True\n'
                               '    except (ValueError, TypeError):\n'
                               '        return False'},
               'ElGamal': {'constants': 'SIG_P, SIG_G = 467, 2',
                           'code': 'def generate_keys():\n'
                                   '    private_key = secrets.randbelow(SIG_P - 2) + 1\n'
                                   '    return private_key, pow(SIG_G, private_key, SIG_P)\n'
                                   '\n'
                                   '\n'
                                   'def sign_message(content, private_key):\n'
                                   '    value = '
                                   'int.from_bytes(hashlib.sha256(content.encode()).digest(), '
                                   '"big")\n'
                                   '    k = secrets.randbelow(SIG_P - 2) + 1\n'
                                   '    while math.gcd(k, SIG_P - 1) != 1:\n'
                                   '        k = secrets.randbelow(SIG_P - 2) + 1\n'
                                   '    r = pow(SIG_G, k, SIG_P)\n'
                                   '    s = ((value - private_key * r) * pow(k, -1, SIG_P - 1)) % '
                                   '(SIG_P - 1)\n'
                                   '    return [r, s], digest_text(content)\n'
                                   '\n'
                                   'def verify_signature(content, signature, public_key):\n'
                                   '    r, s = signature\n'
                                   '    if not (0 < r < SIG_P and 0 <= s < SIG_P - 1):\n'
                                   '        return False\n'
                                   '    value = '
                                   'int.from_bytes(hashlib.sha256(content.encode()).digest(), '
                                   '"big")\n'
                                   '    y = public_key\n'
                                   '    return pow(SIG_G, value, SIG_P) == pow(y, r, SIG_P) * '
                                   'pow(r, s, SIG_P) % SIG_P'},
               'Schnorr': {'constants': 'SIG_P, SIG_Q, SIG_G = '
                                        '(174603574791232246354051371231605080226102972426590404703484661759244705455687110144281032625687997348483286138744890049654307711880324095118542939269921608487240410973422511846587762698868714850355890367869802591444302651887017839068243795781065968467603192888664962425797716555608719325248493301139873058093, '
                                        '1415788254246462573557326432318736449382436643643, '
                                        '66532922375832765569458357633272330911524606757062802983006867719777963116922806290453422052521474726084041409076712888494723042566045983280507959282043750412503955630760900213914798970454838153641377939685649844204321345401500704230511993352319887249032829379614149535962443650838420750542008343644888130928)',
                           'code': 'def generate_keys():\n'
                                   '    private_key = secrets.randbelow(SIG_Q - 1) + 1\n'
                                   '    return private_key, pow(SIG_G, private_key, SIG_P)\n'
                                   '\n'
                                   '\n'
                                   'def challenge(content, commitment):\n'
                                   '    message = json.dumps([content, commitment], '
                                   'ensure_ascii=False).encode()\n'
                                   '    return int.from_bytes(hashlib.sha256(message).digest(), '
                                   '"big") % SIG_Q\n'
                                   '\n'
                                   'def sign_message(content, private_key):\n'
                                   '    k = secrets.randbelow(SIG_Q - 1) + 1\n'
                                   '    r = pow(SIG_G, k, SIG_P)\n'
                                   '    e = challenge(content, r)\n'
                                   '    return [e, (k + private_key * e) % SIG_Q], '
                                   'digest_text(content)\n'
                                   '\n'
                                   'def verify_signature(content, signature, public_key):\n'
                                   '    e, s = signature\n'
                                   '    if not (0 <= e < SIG_Q and 0 <= s < SIG_Q):\n'
                                   '        return False\n'
                                   '    y = public_key\n'
                                   '    r = pow(SIG_G, s, SIG_P) * pow(pow(y, e, SIG_P), -1, '
                                   'SIG_P) % SIG_P\n'
                                   '    return e == challenge(content, r)'}},
 'homomorphic': {'Paillier': 'def encrypt_homomorphic_paillier(m):\n'
                             '    p = 17\n'
                             '    q = 19\n'
                             '    n = p * q\n'
                             '    n2 = n * n\n'
                             '    g = n + 1\n'
                             '    lam = (p - 1) * (q - 1)\n'
                             '    mu = pow(lam, -1, n)\n'
                             '    r = random.randint(1, n - 1)\n'
                             '    while gcd(r, n) != 1:\n'
                             '        r = random.randint(1, n - 1)\n'
                             '    c = (pow(g, m, n2) * pow(r, n, n2)) % n2\n'
                             '    return c,n2\n'
                             '\n'
                             'def decrypt_homomorphic_paillier(c):\n'
                             '    p = 17\n'
                             '    q = 19\n'
                             '    n = p * q\n'
                             '    n2 = n * n\n'
                             '    g = n + 1\n'
                             '    lam = (p - 1) * (q - 1)\n'
                             '    mu = pow(lam, -1, n)\n'
                             '    u = pow(c, lam, n2)\n'
                             '    L = (u - 1) // n\n'
                             '    m = (L * mu) % n\n'
                             '    return m\n'
                             '\n'
                             'def expected_homomorphic(a, b):\n'
                             '    return (a + b) % 323\n'
                             '\n'
                             '\n'
                             'def calculate_homomorphic(a, b):\n'
                             '    if not (0 <= a < 323 and 0 <= b < 323):\n'
                             '        raise ValueError("Use integers from 0 to 322")\n'
                             '    c1, modulus = encrypt_homomorphic_paillier(a)\n'
                             '    c2, modulus = encrypt_homomorphic_paillier(b)\n'
                             '    return {"operation": "addition modulo 323", "ciphertext": c1 * '
                             'c2 % modulus}\n'
                             '\n'
                             '\n'
                             'def decrypt_homomorphic(ciphertext):\n'
                             '    return decrypt_homomorphic_paillier(ciphertext)',
                 'RSA': 'def encrypt_homomorphic_RSA(m):\n'
                        '    p = 11\n'
                        '    q = 13\n'
                        '    n = p * q\n'
                        '    phi = (p - 1) * (q - 1)\n'
                        '    e = 7\n'
                        '    while gcd(e, phi) != 1:\n'
                        '        e += 1\n'
                        '    d = pow(e, -1, phi)\n'
                        '    # print("Public key:", (e, n))\n'
                        '    # print("Private key:", (d, n))\n'
                        '    return pow(m, e, n),n\n'
                        '\n'
                        'def decrypt_homomorphic_RSA(c):\n'
                        '    p = 11\n'
                        '    q = 13\n'
                        '    n = p * q\n'
                        '    phi = (p - 1) * (q - 1)\n'
                        '    e = 7\n'
                        '    while gcd(e, phi) != 1:\n'
                        '        e += 1\n'
                        '    d = pow(e, -1, phi)\n'
                        '    return pow(c, d, n)\n'
                        '\n'
                        'def expected_homomorphic(a, b):\n'
                        '    return (a * b) % 143\n'
                        '\n'
                        '\n'
                        'def calculate_homomorphic(a, b):\n'
                        '    if not (0 <= a < 143 and 0 <= b < 143):\n'
                        '        raise ValueError("Use integers from 0 to 142")\n'
                        '    c1, modulus = encrypt_homomorphic_RSA(a)\n'
                        '    c2, modulus = encrypt_homomorphic_RSA(b)\n'
                        '    return {"operation": "multiplication modulo 143", "ciphertext": c1 * '
                        'c2 % modulus}\n'
                        '\n'
                        '\n'
                        'def decrypt_homomorphic(ciphertext):\n'
                        '    return decrypt_homomorphic_RSA(ciphertext)',
                 'ElGamal': 'HOM_P, HOM_G, HOM_X = 467, 2, 127\n'
                            'HOM_Y = pow(HOM_G, HOM_X, HOM_P)\n'
                            '\n'
                            '\n'
                            'def encrypt_homomorphic_elgamal(m):\n'
                            '    k = secrets.randbelow(HOM_P - 2) + 1\n'
                            '    return pow(HOM_G, k, HOM_P), m * pow(HOM_Y, k, HOM_P) % HOM_P\n'
                            '\n'
                            '\n'
                            'def decrypt_homomorphic(ciphertext):\n'
                            '    a, b = ciphertext\n'
                            '    return b * pow(pow(a, HOM_X, HOM_P), -1, HOM_P) % HOM_P\n'
                            '\n'
                            '\n'
                            'def expected_homomorphic(a, b):\n'
                            '    return a * b % HOM_P\n'
                            '\n'
                            '\n'
                            'def calculate_homomorphic(a, b):\n'
                            '    if not (1 <= a < HOM_P and 1 <= b < HOM_P):\n'
                            '        raise ValueError("Use integers from 1 to 466")\n'
                            '    c1, c2 = encrypt_homomorphic_elgamal(a), '
                            'encrypt_homomorphic_elgamal(b)\n'
                            '    combined = [c1[0] * c2[0] % HOM_P, c1[1] * c2[1] % HOM_P]\n'
                            '    return {"operation": "multiplication modulo 467", "ciphertext": '
                            'combined}'}}

COMMON = {'imports': 'from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP\n'
            'from Crypto.Util.Padding import pad, unpad\n'
            'from Crypto.PublicKey import RSA, ECC\n'
            'from Crypto.Signature import pkcs1_15\n'
            'from Crypto.Hash import SHA256\n'
            'from Crypto.Random import get_random_bytes\n'
            'from pathlib import Path\n'
            'from math import gcd\n'
            'import random\n'
            'import secrets\n'
            'import hashlib\n'
            'import hmac\n'
            'import math\n'
            'import base64\n'
            'import json\n'
            'import re',
 'symmetric': 'def symmetric_encrypt(plaintext, key, iv):\n'
              '    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)\n'
              '    return cipher.encrypt(pad(plaintext.encode(), BLOCK_CIPHER.block_size)).hex()\n'
              '\n'
              '\n'
              'def symmetric_decrypt(ciphertext_hex, key, iv):\n'
              '    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)\n'
              '    return unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), '
              'BLOCK_CIPHER.block_size).decode()',
 'SSE - CREATE ENCRYPTED INDEX AND SEARCH': 'def token(key, word):\n'
                                            '    return hmac.new(key, word.lower().encode(), '
                                            'hashlib.sha256).hexdigest()\n'
                                            '\n'
                                            '\n'
                                            'def create_index(documents, key, iv=None):\n'
                                            '    index = {}\n'
                                            '    for doc_id, doc in documents.items():\n'
                                            '        for word in set(doc.lower().split()):\n'
                                            '            record_iv = '
                                            'get_random_bytes(BLOCK_CIPHER.block_size)\n'
                                            '            enc_id = symmetric_encrypt(doc_id, key, '
                                            'record_iv)\n'
                                            '            index.setdefault(token(SEARCH_KEY, word), '
                                            '[]).append((record_iv.hex(), enc_id))\n'
                                            '    (BASE / '
                                            '"index.json").write_text(json.dumps(index), '
                                            'encoding="utf-8")\n'
                                            '    return index\n'
                                            '\n'
                                            '\n'
                                            'def search(index, query, key, documents=None):\n'
                                            '    results = []\n'
                                            '    for iv_hex, enc_id in index.get(token(SEARCH_KEY, '
                                            'query.strip()), []):\n'
                                            '        doc_id = symmetric_decrypt(enc_id, key, '
                                            'bytes.fromhex(iv_hex))\n'
                                            '        results.append((doc_id, '
                                            'read_document(doc_id)))\n'
                                            '    return results'}

PKSE_TEMPLATE = ('from phe import paillier\n'
 '\n'
 '\n'
 'def pkse_keys():\n'
 '    # Persist a separate Paillier key pair for the lab PKSE index.\n'
 '    key_file = BASE / "keys" / "pkse.json"\n'
 '    key_file.parent.mkdir(parents=True, exist_ok=True)\n'
 '    if key_file.exists():\n'
 '        state = json.loads(key_file.read_text(encoding="utf-8"))\n'
 '        public_key = paillier.PaillierPublicKey(int(state["n"]))\n'
 '        private_key = paillier.PaillierPrivateKey(public_key, int(state["p"]), int(state["q"]))\n'
 '    else:\n'
 '        public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)\n'
 '        state = {"n": str(public_key.n), "p": str(private_key.p), "q": str(private_key.q)}\n'
 '        key_file.write_text(json.dumps(state), encoding="utf-8")\n'
 '    return public_key, private_key\n'
 '\n'
 '\n'
 'def token(key, word):\n'
 '    # Same public SHA256 keyword token as LAB_8_SEARCHABLE_ENCRYPTION/PKSE.py.\n'
 '    # This lab scheme encrypts IDs; it is not trapdoor-based PEKS.\n'
 '    return hashlib.sha256(word.lower().encode()).hexdigest()\n'
 '\n'
 '\n'
 'def create_index(documents, key, iv=None):\n'
 '    public_key, _ = pkse_keys()\n'
 '    index = {}\n'
 "    # Encode filenames as integer chunks within Paillier's positive range.\n"
 '    # Retain byte lengths so UTF-8 and long filenames round-trip exactly.\n'
 '    chunk_size = (public_key.max_int.bit_length() - 1) // 8\n'
 '    for doc_id, doc in documents.items():\n'
 '        raw_id = doc_id.encode("utf-8")\n'
 '        for word in set(doc.lower().split()):\n'
 '            encrypted_id = []\n'
 '            for offset in range(0, len(raw_id), chunk_size):\n'
 '                chunk = raw_id[offset:offset + chunk_size]\n'
 '                encrypted = public_key.encrypt(int.from_bytes(chunk, "big"))\n'
 '                encrypted_id.append([len(chunk), str(encrypted.ciphertext())])\n'
 '            index.setdefault(token(None, word), []).append(encrypted_id)\n'
 '    (BASE / "index.json").write_text(json.dumps(index), encoding="utf-8")\n'
 '    return index\n'
 '\n'
 '\n'
 'def search(index, query, key, documents=None):\n'
 '    public_key, private_key = pkse_keys()\n'
 '    results = []\n'
 '    for encrypted_id in index.get(token(None, query.strip()), []):\n'
 '        parts = []\n'
 '        for length, ciphertext in encrypted_id:\n'
 '            encrypted = paillier.EncryptedNumber(public_key, int(ciphertext))\n'
 '            number = private_key.decrypt(encrypted)\n'
 '            parts.append(number.to_bytes(length, "big"))\n'
 '        doc_id = b"".join(parts).decode("utf-8")\n'
 '        results.append((doc_id, read_document(doc_id)))\n'
 '    return results\n')

OPTIONS = {'symmetric': ('AES-128', 'AES-192', 'AES-256', 'DES', 'Triple-DES'),
 'hash': ('SHA256', 'SHA512', 'SHA1', 'MD5', 'CUSTOM32'),
 'asymmetric': ('RSA', 'ElGamal', 'ECDH', 'DH'),
 'signature': ('RSA', 'ElGamal', 'Schnorr'),
 'homomorphic': ('Paillier', 'RSA', 'ElGamal'),
 'search': ('SSE', 'PKSE')}

LABELS = {'symmetric': 'Document encryption',
 'hash': 'Ciphertext hashing',
 'asymmetric': 'Key encryption / key agreement',
 'signature': 'Digital signature',
 'homomorphic': 'Homomorphic encryption',
 'search': 'Searchable encryption'}

def normalize(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())

def canonical_algorithm(category, value):
    if category not in OPTIONS:
        raise ValueError("Unknown category: " + category)
    cleaned = normalize(value)
    aliases = {
        "symmetric": {"aes": "AES-128", "3des": "Triple-DES", "des3": "Triple-DES", "tdes": "Triple-DES"},
        "asymmetric": {"rsaoaep": "RSA", "ecc": "ECDH", "diffiehellman": "DH"},
        "signature": {"rsapkcs1v15": "RSA"},
    }
    if cleaned in aliases.get(category, {}):
        return aliases[category][cleaned]
    for algorithm in OPTIONS[category]:
        if normalize(algorithm) == cleaned:
            return algorithm
    raise ValueError("Choose one of: " + ", ".join(OPTIONS[category]))

def choose_algorithm(category):
    print("\n" + LABELS[category])
    print("Options: " + " / ".join(OPTIONS[category]))
    if category == "asymmetric":
        print("DH/ECDH derive a shared key to protect the document key.")
    if category == "homomorphic":
        print("Paillier = addition; RSA / ElGamal = multiplication.")
    if category == "search":
        print("SSE or PKSE (Paillier-encrypted IDs, as in the lab). Press Enter to use SSE.")
    while True:
        answer = input("Algorithm name: ").strip()
        if category == "search" and not answer:
            return "SSE"
        try:
            return canonical_algorithm(category, answer)
        except ValueError as exc:
            print(exc)

def section(title, code):
    return ("\n\n# =========================================================\n# " + title +
            "\n# =========================================================\n\n" + code.strip() + "\n")

ACTIONS = {
    "encrypt": "Encrypt and store a new document",
    "decrypt": "Decrypt and view a document",
    "hash": "Hash ciphertext and save its digest",
    "verify_hash": "Verify a saved ciphertext hash",
    "sign": "Create a digital signature",
    "verify_signature": "Verify a digital signature",
    "key_encrypt": "Encrypt/protect the document key",
    "key_decrypt": "Unwrap/check the protected document key",
    "homomorphic_encrypt": "Encrypt two numbers and combine them",
    "homomorphic_decrypt": "Decrypt and check a homomorphic result",
    "build_index": "Build the search index (also requires decrypt permission)",
    "search": "Search encrypted index (returns filenames only)",
    "list": "List stored filenames",
}


def timestamp():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def print(*args, **kwargs):
    text = kwargs.pop("sep", " ").join(str(arg) for arg in args)
    for line in text.split("\n"):
        builtins.print("[" + timestamp() + "] " + line, **kwargs)


def input(prompt=""):
    return builtins.input("[" + timestamp() + "] " + prompt)


RUNTIME = '\nfrom datetime import datetime\nfrom time import perf_counter_ns\nimport builtins\n\nCURRENT_ENTITY = "SYSTEM"\nCURRENT_FILE = None\nTIMINGS = []\n\n\ndef timestamp():\n    return datetime.now().astimezone().isoformat(timespec="milliseconds")\n\n\ndef print(*args, **kwargs):\n    text = kwargs.pop("sep", " ").join(str(arg) for arg in args)\n    for line in text.split("\\n"):\n        builtins.print("[" + timestamp() + "] " + line, **kwargs)\n\n\ndef input(prompt=""):\n    return builtins.input("[" + timestamp() + "] " + prompt)\n\n\ndef record_path(relative):\n    candidate = (BASE / relative).resolve()\n    if not candidate.is_relative_to(BASE.resolve()):\n        raise ValueError("Path must stay within this solution folder.")\n    return candidate\n\n\ndef validate_filename(filename):\n    if (not filename or filename in (".", "..") or\n            any(ch in filename for ch in \'<>:"/\\\\|?*\') or\n            any(ord(ch) < 32 for ch in filename) or\n            filename.endswith((".", " ")) or\n            filename.split(\'.\')[0].upper() in\n            {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],\n             *[f"LPT{i}" for i in range(1, 10)]}):\n        raise ValueError("Enter a plain filename, for example report1.txt")\n    return filename\n\n\ndef read_record(relative):\n    return json.loads(record_path(relative).read_text(encoding="utf-8"))["data"]\n\n\ndef save_record(relative, data):\n    file = record_path(relative)\n    file.parent.mkdir(parents=True, exist_ok=True)\n    now = timestamp()\n    created_at = now\n    if file.exists():\n        created_at = json.loads(file.read_text(encoding="utf-8"))["created_at"]\n    envelope = {"created_at": created_at, "updated_at": now,\n                "entity": CURRENT_ENTITY, "timings": list(TIMINGS), "data": data}\n    file.write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")\n\n\ndef record_event(event):\n    BASE.mkdir(parents=True, exist_ok=True)\n    with (BASE / "audit.jsonl").open("a", encoding="utf-8") as stream:\n        stream.write(json.dumps(event, ensure_ascii=False) + "\\n")\n\n\ndef timed(operation, function, *args, **kwargs):\n    started_at = timestamp()\n    started = perf_counter_ns()\n    status = "success"\n    try:\n        result = function(*args, **kwargs)\n        if result is False:\n            status = "failed"\n        return result\n    except Exception:\n        status = "error"\n        raise\n    finally:\n        duration = (perf_counter_ns() - started) / 1_000_000\n        event = {"started_at": started_at, "finished_at": timestamp(),\n                 "entity": CURRENT_ENTITY, "filename": CURRENT_FILE,\n                 "operation": operation, "status": status, "duration_ms": duration}\n        TIMINGS.append(event)\n        record_event(event)\n        print(f"{operation}: {duration:.6f} ms ({status})")\n\n\ndef initialize():\n    global SERVER_RSA, SERVER_ECC, PRIVATE_X, PUBLIC_Y, KEY, SEARCH_KEY\n    for name in ("encrypted", "hashes", "signature", "public_key", "add", "metadata", "keys", "verification"):\n        (BASE / name).mkdir(parents=True, exist_ok=True)\n    if record_path("keys/local.json").exists():\n        state = read_record("keys/local.json")\n    else:\n        state = {"symmetric": get_random_bytes(KEY_BYTES).hex(),\n                 "search": get_random_bytes(32).hex()}\n        if ASYMMETRIC == "RSA":\n            state["private"] = timed("key_generation", RSA.generate, 2048).export_key().decode()\n        elif ASYMMETRIC == "ECDH":\n            state["private"] = timed("key_generation", ECC.generate, curve="P-256").export_key(format="PEM")\n        else:\n            state["private"] = secrets.randbelow(P - 3) + 2\n        save_record("keys/local.json", state)\n    if ASYMMETRIC == "RSA":\n        SERVER_RSA = RSA.import_key(state["private"])\n    elif ASYMMETRIC == "ECDH":\n        SERVER_ECC = ECC.import_key(state["private"])\n    else:\n        PRIVATE_X = state["private"]\n        PUBLIC_Y = pow(G, PRIVATE_X, P)\n    KEY = bytes.fromhex(state["symmetric"])\n    SEARCH_KEY = bytes.fromhex(state["search"])\n    return KEY, SEARCH_KEY\n\n\ndef ciphertext(filename):\n    return read_record("encrypted/" + filename)\n\n\ndef decrypt_record(filename):\n    metadata = read_record("metadata/" + filename)\n    return symmetric_decrypt(ciphertext(filename), KEY, bytes.fromhex(metadata["iv"]))\n\n\ndef require_permission(entity, action):\n    if entity not in ENTITIES or action not in ENTITIES[entity]:\n        raise PermissionError(f"{entity} is not allowed to perform {action}.")\n    if action == "build_index" and "decrypt" not in ENTITIES[entity]:\n        raise PermissionError("Building the index also requires decrypt permission.")\n\n\ndef perform(entity, action, filename=None, **values):\n    global CURRENT_ENTITY, CURRENT_FILE, TIMINGS\n    CURRENT_ENTITY, CURRENT_FILE, TIMINGS = entity, filename, []\n    started_at, started = timestamp(), perf_counter_ns()\n    status = "success"\n    try:\n        require_permission(entity, action)\n        if action not in ("list", "build_index", "search"):\n            filename = validate_filename(filename or "")\n        if action == "encrypt":\n            if record_path("encrypted/" + filename).exists():\n                raise ValueError("Document already exists.")\n            iv = get_random_bytes(BLOCK_CIPHER.block_size)\n            encrypted = timed("encryption", symmetric_encrypt, values["plaintext"], KEY, iv)\n            save_record("encrypted/" + filename, encrypted)\n            save_record("metadata/" + filename, {"iv": iv.hex()})\n            # An existing index is now stale; a permitted entity must rebuild it.\n            if record_path("index.json").exists():\n                save_record("index_status.json", {"stale": True})\n            print("Document encrypted:", filename)\n            return filename\n        if action == "decrypt":\n            plaintext = timed("decryption", decrypt_record, filename)\n            print("Plaintext:")\n            print(plaintext)\n            return plaintext\n        if action == "hash":\n            digest = timed("hashing", digest_text, ciphertext(filename))\n            save_record("hashes/" + filename, digest)\n            print("Hash:", digest)\n            return digest\n        if action == "verify_hash":\n            digest = timed("hashing", digest_text, ciphertext(filename))\n            result = timed("hash_verification", hmac.compare_digest, digest, read_record("hashes/" + filename))\n            save_record("verification/hash_" + filename, {"verified": result})\n            print("Hash verified:", result)\n            if not result:\n                status = "failed"\n            return result\n        if action == "sign":\n            private_key, public_key = timed("signature_key_generation", generate_keys)\n            # sign_message keeps the original signature API; its digest is not\n            # saved here, because hashing is an independently assigned action.\n            signature, _ = timed("signature_generation", sign_message, ciphertext(filename), private_key)\n            save_record("signature/" + filename, signature)\n            save_record("public_key/" + filename, public_key)\n            print("Document signed:", filename)\n            return signature\n        if action == "verify_signature":\n            result = timed("signature_verification", verify_signature, ciphertext(filename),\n                           read_record("signature/" + filename), read_record("public_key/" + filename))\n            save_record("verification/signature_" + filename, {"verified": result})\n            print("Signature verified:", result)\n            if not result:\n                status = "failed"\n            return result\n        if action == "key_encrypt":\n            metadata = read_record("metadata/" + filename)\n            metadata["wrapped_key"] = timed("key_encryption", wrap_key, KEY)\n            save_record("metadata/" + filename, metadata)\n            print("Document key protected.")\n            return True\n        if action == "key_decrypt":\n            metadata = read_record("metadata/" + filename)\n            recovered = timed("key_decryption", unwrap_key, metadata["wrapped_key"])\n            result = hmac.compare_digest(recovered, KEY)\n            save_record("verification/key_" + filename, {"verified": result})\n            print("Recovered key matches:", result)\n            if not result:\n                status = "failed"\n            return result\n        if action == "homomorphic_encrypt":\n            ciphertext(filename)  # Require an existing document.\n            a, b = values["num1"], values["num2"]\n            result = timed("homomorphic_encryption_and_combination", calculate_homomorphic, a, b)\n            result.update(num1=a, num2=b)\n            save_record("add/" + filename, result)\n            print("Encrypted", result["operation"], ":", result["ciphertext"])\n            return result\n        if action == "homomorphic_decrypt":\n            saved = read_record("add/" + filename)\n            result = timed("homomorphic_decryption", decrypt_homomorphic, saved["ciphertext"])\n            valid = result == expected_homomorphic(saved["num1"], saved["num2"])\n            save_record("verification/homomorphic_" + filename, {"result": result, "verified": valid})\n            print("Homomorphic result:", result, "verified:", valid)\n            if not valid:\n                status = "failed"\n            return result\n        if action == "build_index":\n            documents = {}\n            for file in sorted((BASE / "encrypted").iterdir()):\n                if file.is_file():\n                    documents[file.name] = timed("index_document_decryption", decrypt_record, file.name)\n            index = timed("index_creation", create_index, documents, KEY)\n            save_record("index.json", index)\n            save_record("index_status.json", {"stale": False})\n            print("Search index created for", len(documents), "documents.")\n            return len(documents)\n        if action == "search":\n            if record_path("index_status.json").exists() and read_record("index_status.json")["stale"]:\n                raise ValueError("The index is stale. Ask an entity with build_index permission to rebuild it.")\n            query = values["query"].strip()\n            if len(query.split()) != 1:\n                raise ValueError("Enter one search word.")\n            results = timed("search", search, read_record("index.json"), query, KEY)\n            print("Matching filenames:", ", ".join(results) if results else "None")\n            return results\n        if action == "list":\n            results = sorted(file.name for file in (BASE / "encrypted").iterdir() if file.is_file())\n            print("Stored filenames:", ", ".join(results) if results else "None")\n            return results\n        raise ValueError("Unknown action.")\n    except PermissionError:\n        status = "denied"\n        raise\n    except Exception:\n        status = "error"\n        raise\n    finally:\n        event = {"started_at": started_at, "finished_at": timestamp(), "entity": entity,\n                 "filename": filename, "operation": "action:" + action, "status": status,\n                 "duration_ms": (perf_counter_ns() - started) / 1_000_000}\n        record_event(event)\n        # Overall action duration includes file I/O; timed crypto entries measure\n        # just the named function. Store both, without plaintext or key values.\n        with (BASE / "timings.jsonl").open("a", encoding="utf-8") as stream:\n            stream.write(json.dumps({**event, "steps": list(TIMINGS)}) + "\\n")\n        CURRENT_ENTITY, CURRENT_FILE = "SYSTEM", None\n\n\nWORKFLOW_ORDER = (\n    "encrypt", "key_encrypt", "hash", "sign", "verify_hash", "verify_signature",\n    "key_decrypt", "decrypt", "homomorphic_encrypt", "homomorphic_decrypt",\n    "build_index", "search", "list",\n)\n\n\ndef run_workflow(entity, filename=None, **values):\n    if entity not in ENTITIES:\n        raise PermissionError("Unknown entity.")\n    allowed = ENTITIES[entity]\n    report = {"completed": [], "skipped": [], "failed": []}\n    if any(action not in ("list", "build_index", "search") for action in allowed):\n        filename = validate_filename(filename or "")\n    for action in WORKFLOW_ORDER:\n        if action not in allowed:\n            continue\n        # Reusing a record must not overwrite the evidence to be verified.\n        existing = {"encrypt": "encrypted/", "hash": "hashes/", "sign": "signature/",\n                    "homomorphic_encrypt": "add/"}\n        if action in existing and record_path(existing[action] + filename).exists():\n            print("Already saved; reusing:", ACTIONS[action])\n            report["skipped"].append(action)\n            continue\n        if action == "key_encrypt" and record_path("metadata/" + filename).exists():\n            if "wrapped_key" in read_record("metadata/" + filename):\n                print("Already saved; reusing protected key.")\n                report["skipped"].append(action)\n                continue\n        try:\n            result = perform(entity, action, filename, **values)\n            if result is False:\n                print("Workflow stopped: verification failed. Remaining steps were not run.")\n                report["failed"].append(action)\n                break\n            if action == "homomorphic_decrypt":\n                saved = read_record("add/" + filename)\n                if result != expected_homomorphic(saved["num1"], saved["num2"]):\n                    print("Workflow stopped: homomorphic verification failed.")\n                    report["failed"].append(action)\n                    break\n            report["completed"].append(action)\n        except FileNotFoundError:\n            print("Not ready:", ACTIONS[action], "- a required record/artifact must be created by its permitted entity first.")\n            report["skipped"].append(action)\n        except (ValueError, OSError, KeyError, TypeError, PermissionError) as exc:\n            print("Workflow stopped:", ACTIONS[action], "-", exc)\n            report["failed"].append(action)\n            break\n    print("Workflow finished:", len(report["completed"]), "completed,",\n          len(report["skipped"]), "reused/not ready,", len(report["failed"]), "failed.")\n    return report\n\n\ndef main():\n    initialize()\n    names = list(ENTITIES)\n    while True:\n        print("\\n" + TITLE)\n        print("Choose an entity to run its permitted workflow (local lab role simulation):")\n        for number, name in enumerate(names, 1):\n            print(f"{number}. {name}")\n        print("0. Exit")\n        choice = input("Entity: ").strip()\n        if choice == "0":\n            break\n        if not choice.isdigit() or not 1 <= int(choice) <= len(names):\n            print("Invalid entity.")\n            continue\n        entity = names[int(choice) - 1]\n        allowed = ENTITIES[entity]\n        if not allowed:\n            print("This entity has no assigned operations.")\n            continue\n        print("Automatic steps:", " -> ".join(action for action in WORKFLOW_ORDER if action in allowed))\n        try:\n            filename, values = None, {}\n            if any(action not in ("list", "build_index", "search") for action in allowed):\n                filename = validate_filename(input("Filename: ").strip())\n            if "encrypt" in allowed and not record_path("encrypted/" + filename).exists():\n                values["plaintext"] = input("Document text: ")\n            if "homomorphic_encrypt" in allowed and not record_path("add/" + filename).exists():\n                values["num1"] = int(input("First integer: "))\n                values["num2"] = int(input("Second integer: "))\n            if "search" in allowed:\n                values["query"] = input("Search word: ")\n            run_workflow(entity, filename, **values)\n        except (ValueError, OSError, KeyError, TypeError, PermissionError) as exc:\n            print("Workflow could not complete:", exc)\n\n\n\nif __name__ == "__main__":\n    try:\n        main()\n    except (KeyboardInterrupt, EOFError):\n        print("Program closed.")\n'

def validate_entities(entities):
    if not isinstance(entities, dict) or not entities:
        raise ValueError("Configure at least one named entity.")
    result = {}
    seen = set()
    for name, permissions in entities.items():
        if not isinstance(name, str) or not name.strip() or any(ord(ch) < 32 for ch in name):
            raise ValueError("Entity names must be nonempty text without control characters.")
        name = name.strip()
        if name.casefold() in seen:
            raise ValueError("Entity names must be unique (ignoring case).")
        seen.add(name.casefold())
        if not isinstance(permissions, (list, tuple, set)) or any(p not in ACTIONS for p in permissions):
            raise ValueError("Use only the listed permission names.")
        if "build_index" in permissions and "decrypt" not in permissions:
            raise ValueError(name + ": build_index also requires decrypt permission.")
        result[name] = [action for action in ACTIONS if action in permissions]
    return result


def choose_entities():
    while True:
        count = input("How many entities? ").strip()
        if count.isdigit() and 1 <= int(count) <= 100:
            break
        print("Enter an entity count from 1 to 100.")
    print("Your selected permissions become one automatic workflow for each entity.")
    print("Entity selection is a local lab simulation, without password authentication.")
    entities = {}
    action_names = list(ACTIONS)
    for number in range(1, int(count) + 1):
        while True:
            name = input(f"Name of entity {number}: ").strip()
            if name and not any(ord(ch) < 32 for ch in name) and name.casefold() not in {n.casefold() for n in entities}:
                break
            print("Enter a unique, nonempty entity name.")
        print("Allowed actions for " + name + ":")
        for index, action in enumerate(action_names, 1):
            print(f"{index}. {action}: {ACTIONS[action]}")
        while True:
            answer = input("Enter comma-separated numbers or action names, all, or none: ").strip().lower()
            try:
                if answer == "all":
                    permissions = action_names[:]
                elif answer == "none":
                    permissions = []
                else:
                    permissions = []
                    for item in answer.split(","):
                        item = item.strip()
                        if item.isdigit() and 1 <= int(item) <= len(action_names):
                            item = action_names[int(item) - 1]
                        if item not in ACTIONS:
                            raise ValueError("Unknown action: " + item)
                        permissions.append(item)
                entities.update(validate_entities({name: permissions}))
                break
            except ValueError as exc:
                print(exc)
    return entities


def build_source(title, algorithms, entities):
    selected = {name: canonical_algorithm(name, algorithms[name]) for name in OPTIONS}
    entities = validate_entities(entities)
    asymmetric = TEMPLATES["asymmetric"][selected["asymmetric"]]
    signature = TEMPLATES["signature"][selected["signature"]]
    code = "# Generated at " + timestamp() + "\n" + COMMON["imports"] + "\n\n"
    code += "TITLE = " + repr(title) + "\n"
    code += "ASYMMETRIC = " + repr(selected["asymmetric"]) + "\n"
    code += "ENTITIES = " + repr(entities) + "\n"
    code += "ACTIONS = " + repr(ACTIONS) + "\n"
    code += "BASE = Path(__file__).resolve().parent\n"
    code += TEMPLATES["symmetric"][selected["symmetric"]] + "\n"
    code += asymmetric["constants"] + "\n" + signature["constants"] + "\n"
    search_code = PKSE_TEMPLATE if selected["search"] == "PKSE" else COMMON["SSE - CREATE ENCRYPTED INDEX AND SEARCH"]
    # Only this enhanced copy changes the storage format: timestamped JSON envelopes.
    search_code = search_code.replace(
        '(BASE / "index.json").write_text(json.dumps(index), encoding="utf-8")',
        'save_record("index.json", index)')
    search_code = search_code.replace('results.append((doc_id, read_document(doc_id)))', 'results.append(doc_id)')
    search_code = search_code.replace('json.loads(key_file.read_text(encoding="utf-8"))', 'read_record("keys/pkse.json")')
    search_code = search_code.replace('key_file.write_text(json.dumps(state), encoding="utf-8")', 'save_record("keys/pkse.json", state)')
    code += section(selected["search"] + " - CREATE ENCRYPTED INDEX AND SEARCH", search_code)
    code += section("HOMOMORPHIC ENCRYPTION AND DECRYPTION", TEMPLATES["homomorphic"][selected["homomorphic"]])
    # Avoid computing the separately selected integrity hash during signing.
    signature_code = signature["code"].replace('digest_text(message)', 'None').replace('digest_text(content)', 'None')
    code += section("GENERATE KEYS, SIGN MESSAGE AND VERIFY SIGNATURE", TEMPLATES["hash"][selected["hash"]] + "\n\n" + signature_code)
    code += section(selected["symmetric"] + " ENCRYPTION AND DECRYPTION", COMMON["symmetric"])
    code += section(selected["asymmetric"] + " KEY PROTECTION", asymmetric["code"])
    code += section("TIMESTAMPS, TIMINGS, FILES AND ENTITY PERMISSIONS", RUNTIME)
    ast.parse(code)
    return code, selected, entities


def create_solution(title, algorithms, output_dir, entities):
    if not title.strip():
        raise ValueError("Enter a project name.")
    code, selected, entities = build_source(title.strip(), algorithms, entities)
    created_at = timestamp()
    requirements = "# Created at " + created_at + "\npycryptodome>=3.20\n"
    if selected["search"] == "PKSE":
        requirements += "phe>=1.5.0\n"
    guide = f"""{title.strip()} - TIMESTAMPED ENTITY-BASED CRYPTO LAB
Created at: {created_at}

Run:
  python -m pip install -r requirements.txt
  python solution.py

ALGORITHMS
""" + "\n".join(f"  {LABELS[k]}: {v}" for k, v in selected.items()) + "\n\nENTITIES AND PERMISSIONS\n" + "\n".join(
        "  " + name + ": " + (", ".join(permissions) or "none") for name, permissions in entities.items()) + """

Select an entity and enter its needed inputs once. Its permitted steps run automatically:
1. An entity with encrypt permission stores the document.
2. An entity with hash permission saves its ciphertext hash.
3. An entity with sign permission saves its signature and verification key.
4. Entities with verify_hash and verify_signature check those artifacts.
5. An entity with decrypt permission can read the plaintext.
6. An entity with key_encrypt can protect the document key; key_decrypt checks it.
7. homomorphic_encrypt saves a combined encrypted result; homomorphic_decrypt checks it.
8. An entity with BOTH build_index and decrypt builds the index.
9. An entity with search sees matching filenames only, without plaintext access.

The application checks permissions even for direct perform() calls, and menus
run only allowed actions. The workflow never grants extra permissions. Entity selection is a local lab role simulation,
not password authentication or protection against someone editing Python or
reading local private keys. entities.json documents the generated policy;
the standalone program embeds that same policy in ENTITIES.
Key wrapping/unwrapping are independently permissioned demonstrations.
Document decryption uses the local document key. If the entity has verification
permissions, those checks run before decryption. A failed check stops its workflow.
Existing ciphertext/hashes/signatures/results are reused, never overwritten by
the workflow. Missing artifacts are reported as not ready for that step.
Create a new filename to process a new version of a document.
Signature-internal SHA256 is inherent to signing, separate from the hash action.
Adding a document marks an existing index stale; rebuild it before searching.

TIMESTAMPS AND TIMINGS
Every terminal message and prompt has an ISO timestamp with timezone offset.
All runtime JSON records contain created_at, updated_at, entity, timings, data.
Source/configuration/requirements/ignore files also carry creation timestamps.
Ciphertext, hashes and signatures are inside the data field, not bare text.
Timestamps and timings are metadata; signatures cover ciphertext only.
Audit/timing logs use started_at, finished_at and duration_ms for each event.
Per-operation timing uses a monotonic high-resolution clock and measures the
named function only; total action timing also includes I/O and log overhead.
Verification steps are recorded even when they return false. Denials and errors
are recorded too. Logs do not contain document plaintext or key material.
Timestamps reflect the local machine's timezone, including its UTC offset.

FILES
  encrypted/<filename>   encrypted document
  metadata/<filename>    IV and optional protected document key
  hashes/<filename>      selected hash of the ciphertext
  signature/<filename>   signature of the ciphertext
  public_key/<filename>  signature verification key
  add/<filename>         encrypted homomorphic result and original two numbers
  verification/          saved hash/signature/key/homomorphic check results
  keys/local.json        persistent local symmetric/search/private keys
  keys/pkse.json         separate Paillier search keys, for PKSE only
  index.json             encrypted filename index
  index_status.json      whether the index needs rebuilding
  audit.jsonl            timestamped operation and permission audit log
  timings.jsonl          each action's elapsed time and detailed step timings

SSE uses HMAC-SHA256 tokens and symmetrically encrypted filenames.
PKSE matches the lab: SHA256 keyword tokens and Paillier-encrypted filenames.
This lab PKSE is not trapdoor-based PEKS; public hashes permit guessed-word lookup.
Both searches ignore case and use whitespace-delimited single words.
No sockets are used. No classical ciphers are included.
Paillier: 0..322, addition modulo 323. RSA homomorphic: 0..142, multiply modulo 143.
ElGamal homomorphic: 1..466, multiply modulo 467. Try 7 and 3 (10 or 21).
Legacy ciphers, small textbook groups and local private keys are educational.
"""
    artifacts = {
        "solution.py": code,
        "algos_used.json": json.dumps({"created_at": created_at, "algorithms": selected}, indent=2) + "\n",
        "entities.json": json.dumps({"created_at": created_at, "entities": entities}, indent=2, ensure_ascii=False) + "\n",
        "requirements.txt": requirements,
        ".gitignore": "# Created at " + created_at + "\n__pycache__/\n*.py[cod]\nkeys/\nencrypted/\nhashes/\nsignature/\npublic_key/\nadd/\nmetadata/\nverification/\nindex.json\nindex_status.json\naudit.jsonl\ntimings.jsonl\n",
        "RUN.txt": guide,
    }
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    for name, content in artifacts.items():
        (directory / name).write_text(content, encoding="utf-8")
    return directory / "solution.py"


def main():
    print("CRYPTO LAB GENERATOR - CUSTOM ENTITIES AND TIMESTAMPS")
    print("SSE/PKSE, independent permissions and operation timings. No classical ciphers.")
    title = input("Project name: ").strip()
    while not title:
        title = input("Enter a project name: ").strip()
    selected = {category: choose_algorithm(category) for category in OPTIONS}
    entities = choose_entities()
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", title).strip("_")[:80] or "solution"
    default = Path(__file__).resolve().parent / "GENERATED_ENTITY_SOLUTIONS" / ("CUSTOM_" + slug)
    print("Selected algorithms:", json.dumps(selected))
    for name, permissions in entities.items():
        print(name + ": " + (", ".join(permissions) or "none"))
    while True:
        answer = input("New output folder (Enter for " + str(default) + "): ").strip()
        try:
            file = create_solution(title, selected, Path(answer).expanduser() if answer else default, entities)
            break
        except FileExistsError:
            print("That folder already exists. Choose a new folder to preserve existing files and keys.")
        except (ValueError, OSError) as exc:
            print("Could not create solution:", exc)
    print("Created:", file)
    print("Open its folder and run: python -m pip install -r requirements.txt")
    print("Then run: python solution.py")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("Generator closed.")
