# Install dependency:
# python -m pip install pycryptodome
#
# File-based, menu-driven lab solution. No sockets.
# Timestamp trust and two-authority separation are simulated locally.
# A real deployment needs separate authority machines and a trusted time service.

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

from pathlib import Path
from datetime import datetime, timedelta, timezone
from time import perf_counter
from getpass import getpass
from math import gcd, lcm

import hashlib
import hmac
import json
import secrets
import os
import re


BASE = Path(__file__).resolve().parent / "record_files"
IST = timezone(timedelta(hours=5, minutes=30))
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"



ROLE = None
EVENTS = []

FOLDERS = [
    "keys",
    "authorities",
    "encrypted",
    "encrypted_key",
    "iv",
    "hashes",
    "signature",
    "public_key",
    "paillier",
    "metadata",
    "index",
    "receipts",
    "verified",
    "tally",
]


# =========================================================
# FILE STORAGE, TIMESTAMPS AND TIMINGS
# =========================================================


ALGORITHMS = {'encryption': 'AES-192', 'hash': 'SHA-512', 'key': 'RSA', 'signature': 'RSA', 'search': 'PKSE', 'rsa_bits': {'key': 2048, 'signature': 3072, 'search': 2048}}

DOMAIN = {'title': 'warehouse inventory system', 'record_name': 'application', 'fields': [{'name': 'supplier_name', 'type': 'text', 'search': True, 'sum': False, 'count': False}, {'name': 'category', 'type': 'text', 'search': True, 'sum': False, 'count': False}, {'name': 'quantity', 'type': 'integer', 'search': False, 'sum': True, 'count': False}, {'name': 'delivery_cost', 'type': 'decimal', 'search': False, 'sum': True, 'count': False, 'decimals': 2}], 'use_deadline': False, 'close_on_aggregate': False, 'min_records': 3}
ENTITIES = {'Storekeeper': ['submit_record'], 'Inspector': ['verify_record', 'view_record', 'search_records'], 'Warehouse manager': ['aggregate_records', 'threshold_decrypt']}
DOMAIN_ACTIONS = {'submit_record': 'Submit record: hash, sign, encrypt, protect key, encrypt totals and index', 'verify_record': 'Verify record: decrypt internally, compare hashes/signature and validate metadata', 'view_record': 'Verify and display plaintext record', 'search_records': 'Search configured fields or submission time (IDs only)', 'aggregate_records': 'Aggregate all verified encrypted totals and category counts', 'threshold_decrypt': 'Decrypt aggregate using both authority passwords'}
METRICS = {'record_count': {'kind': 'record_count', 'label': 'Record count', 'scale': 1, 'decimals': 0}, 'sum_2': {'kind': 'sum', 'label': 'Total quantity', 'field': 'quantity', 'scale': 1, 'decimals': 0}, 'sum_3': {'kind': 'sum', 'label': 'Total delivery_cost', 'field': 'delivery_cost', 'scale': 100, 'decimals': 2}}

def now():
    return datetime.now(IST).strftime(TIME_FORMAT)

def save(folder, filename, value):
    path = BASE / folder / filename
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")

def read(folder, filename):
    path = BASE / folder / filename
    return json.loads(path.read_text(encoding="utf-8"))

def timed(operation, function, *args):
    started_at = datetime.now(IST).isoformat(timespec="milliseconds")
    start = perf_counter()
    status = "success"

    try:
        result = function(*args)

        if result is False:
            status = "failed"

        return result

    except Exception:
        status = "error"
        raise

    finally:
        EVENTS.append({
            "operation": operation,
            "started_at": started_at,
            "finished_at": datetime.now(IST).isoformat(
                timespec="milliseconds"
            ),
            "duration_ms": (perf_counter() - start) * 1000,
            "status": status,
        })

def show_summary(action, details):
    timestamp = datetime.now(IST).isoformat(timespec="milliseconds")

    print(f"\n[{timestamp}] {ROLE.upper()} - {action}")

    for name, value in details.items():
        print(name + ":", value)

    totals = {}

    for event in EVENTS:
        name = event["operation"]
        totals[name] = totals.get(name, 0) + event["duration_ms"]

    if totals:
        print(
            "Times (ms):",
            " | ".join(
                f"{name}={duration:.6f}"
                for name, duration in totals.items()
            ),
        )

    entry = {
        "timestamp": timestamp,
        "role": ROLE,
        "action": action,
        "details": details,
        "events": list(EVENTS),
    }

    with (BASE / "events.jsonl").open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")

def password_key(password, salt):
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )

def new_password(label):
    while True:
        password = getpass(f"Set {label} password: ")
        confirmation = getpass("Confirm password: ")

        if password and password == confirmation:
            return password

        print("Passwords must be nonempty and match.")

def login(role):
    account = read("keys", "accounts.json")[role]
    password = getpass(f"{role.capitalize()} password: ")

    actual = password_key(
        password,
        bytes.fromhex(account["salt"]),
    ).hex()

    if not hmac.compare_digest(actual, account["hash"]):
        print("Access denied.")
        return False

    return True

def protect_share(number, share, password):
    salt = os.urandom(16)
    key = password_key(password, salt)

    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(
        str(share).encode()
    )

    save("authorities", f"{number}.json", {
        "salt": salt.hex(),
        "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    })

def unlock_share(number, password):
    record = read("authorities", f"{number}.json")

    key = password_key(
        password,
        bytes.fromhex(record["salt"]),
    )

    cipher = AES.new(
        key,
        AES.MODE_EAX,
        nonce=bytes.fromhex(record["nonce"]),
    )

    plaintext = cipher.decrypt_and_verify(
        bytes.fromhex(record["ciphertext"]),
        bytes.fromhex(record["tag"]),
    )

    return int(plaintext.decode())

def setup():
    for folder in FOLDERS:
        (BASE / folder).mkdir(parents=True, exist_ok=True)

    if (BASE / "keys" / "settings.json").exists():
        return

    if any((BASE / "keys").iterdir()):
        raise ValueError(
            "Incomplete setup. Use a fresh record_files folder."
        )

    print("\nFIRST-RUN SYSTEM SETUP")
    print("Enter dates in IST using YYYY-MM-DD HH:MM:SS.")

    start = datetime(1970, 1, 1)
    deadline = datetime(9999, 12, 31, 23, 59, 59)

    accounts = {}

    for role in ENTITIES:
        password = new_password(role)
        salt = os.urandom(16)

        accounts[role] = {
            "salt": salt.hex(),
            "hash": password_key(password, salt).hex(),
        }

    authority_passwords = [
        new_password("authority 1"),
        new_password("authority 2"),
    ]

    if ALGORITHMS["key"] == "RSA":
        print("Generating RSA-" + str(ALGORITHMS["rsa_bits"]["key"]) + " keys...")

        rsa_key = RSA.generate(ALGORITHMS["rsa_bits"]["key"])

        save(
            "keys",
            "rsa_private.json",
            rsa_key.export_key().decode(),
        )

        save(
            "keys",
            "rsa_public.json",
            rsa_key.publickey().export_key().decode(),
        )

    print("Generating Paillier parameters...")

    while True:
        p = getPrime(1024)
        q = getPrime(1024)

        n = p * q
        lam = lcm(p - 1, q - 1)

        if p != q and gcd(lam, n) == 1:
            break

    # d is divisible by lambda, and d mod n = 1.
    # Therefore L(c^d mod n²) recovers the plaintext modulo n.
    d = lam * pow(lam, -1, n)
    period = n * lam

    share1 = secrets.randbelow(period - 1) + 1
    share2 = (d - share1) % period

    protect_share(1, share1, authority_passwords[0])
    protect_share(2, share2, authority_passwords[1])

    save("keys", "paillier_public.json", {
        "n": n,
        "g": n + 1,
    })

    # Do not persist p, q, lambda or the complete exponent d.
    del p, q, lam, d, period, share1, share2

    print("Generating educational ElGamal parameters...")

    elgamal = ElGamal.generate(512, os.urandom)

    save("keys", "elgamal.json", {
        "p": int(elgamal.p),
        "g": int(elgamal.g),
    })

    save("keys", "accounts.json", accounts)
    save("keys", "search_key.json", os.urandom(32).hex())
    save("keys", "receipt_key.json", os.urandom(32).hex())

    save("keys", "settings.json", {
        "start": start.strftime(TIME_FORMAT),
        "deadline": deadline.strftime(TIME_FORMAT),
        "created_at": now(),
    })

    print("Setup complete.")

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(plaintext.encode(), AES.block_size)
    )

    return cipher.iv.hex(), ciphertext.hex()

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=bytes.fromhex(iv),
    )

    plaintext = unpad(
        cipher.decrypt(bytes.fromhex(ciphertext)),
        AES.block_size,
    )

    return plaintext.decode()

def rsa_encrypt_key(key):
    public_key = RSA.import_key(
        read("keys", "rsa_public.json")
    )

    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    return cipher.encrypt(key).hex()

def rsa_decrypt_key(ciphertext):
    private_key = RSA.import_key(
        read("keys", "rsa_private.json")
    )

    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)

    return cipher.decrypt(bytes.fromhex(ciphertext))

def hash_message(message):
    return hashlib.sha512(message.encode()).hexdigest()

def generate_signing_keys():
    parameters = read("keys", "elgamal.json")

    p = parameters["p"]
    g = parameters["g"]

    private_key = secrets.randbelow(p - 2) + 1

    public_key = {
        "p": p,
        "g": g,
        "y": pow(g, private_key, p),
    }

    return private_key, public_key

def sign_hash(digest, private_key, public_key):
    p = public_key["p"]
    g = public_key["g"]

    while True:
        k = secrets.randbelow(p - 2) + 1

        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)

    s = (
        (int(digest, 16) - private_key * r)
        * pow(k, -1, p - 1)
    ) % (p - 1)

    return [r, s]

def signature_values(digest, signature, public_key):
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]

    r, s = signature

    if not (0 < r < p and 0 <= s < p - 1):
        raise ValueError("Invalid ElGamal signature values.")

    expected = pow(g, int(digest, 16), p)

    actual = (
        pow(y, r, p) * pow(r, s, p)
    ) % p

    return expected, actual

def verify_signature(digest, signature, public_key):
    expected, actual = signature_values(
        digest, signature, public_key
    )

    return expected == actual

def paillier_encrypt(message, n):
    if not 0 <= message < n:
        raise ValueError("Message outside Paillier range.")

    while True:
        r = secrets.randbelow(n - 1) + 1

        if gcd(r, n) == 1:
            break

    ciphertext = (
        pow(n + 1, message, n * n)
        * pow(r, n, n * n)
    ) % (n * n)

    return ciphertext, r

def search_token(value):
    key = bytes.fromhex(read("keys", "search_key.json"))

    return hmac.new(
        key,
        value.encode(),
        hashlib.sha256,
    ).hexdigest()

def seal(value):
    key = bytes.fromhex(read("keys", "receipt_key.json"))

    data = json.dumps(value, sort_keys=True).encode()

    return hmac.new(
        key,
        data,
        hashlib.sha256,
    ).hexdigest()


from Crypto.Cipher import DES, DES3
from Crypto.PublicKey import ECC, DSA
from Crypto.Protocol.DH import key_agreement
from Crypto.Signature import pkcs1_15

_original_setup = setup
_original_generate_signing_keys = generate_signing_keys
_original_sign_hash = sign_hash
_original_signature_values = signature_values
_original_encrypt_key = rsa_encrypt_key
_original_decrypt_key = rsa_decrypt_key
_original_search_token = search_token


def setup():
    _original_setup()
    if ALGORITHMS['key'] == 'ECDH' and not (BASE/'keys'/'ecdh_private.json').exists():
        key = ECC.generate(curve='P-256')
        save('keys', 'ecdh_private.json', key.export_key(format='PEM'))
        save('keys', 'ecdh_public.json', key.public_key().export_key(format='PEM'))
    if ALGORITHMS['signature'] == 'Schnorr' and not (BASE/'keys'/'schnorr.json').exists():
        group = DSA.generate(2048)
        save('keys', 'schnorr.json', {name: int(getattr(group, name)) for name in ('p','q','g')})
    if ALGORITHMS['search'] == 'PKSE' and not (BASE/'keys'/'search_private.json').exists():
        key = RSA.generate(ALGORITHMS['rsa_bits']['search'])
        save('keys', 'search_private.json', key.export_key().decode())
        save('keys', 'search_public.json', key.publickey().export_key().decode())


def document_key():
    size = {'AES-128':16, 'AES-192':24, 'AES-256':32, 'DES':8, 'Triple-DES':24}[ALGORITHMS['encryption']]
    key = os.urandom(size)
    return DES3.adjust_key_parity(key) if ALGORITHMS['encryption'] == 'Triple-DES' else key


def document_cipher():
    return {'DES':DES, 'Triple-DES':DES3}.get(ALGORITHMS['encryption'], AES)


def aes_encrypt(plaintext, key):
    algorithm = document_cipher()
    cipher = algorithm.new(key, algorithm.MODE_CBC)
    return cipher.iv.hex(), cipher.encrypt(pad(plaintext.encode(), algorithm.block_size)).hex()


def aes_decrypt(ciphertext, key, iv):
    algorithm = document_cipher()
    cipher = algorithm.new(key, algorithm.MODE_CBC, iv=bytes.fromhex(iv))
    return unpad(cipher.decrypt(bytes.fromhex(ciphertext)), algorithm.block_size).decode()


def hash_message(message):
    return hashlib.new(ALGORITHMS['hash'].lower().replace('-', ''), message.encode()).hexdigest()


def rsa_encrypt_key(key):
    if ALGORITHMS['key'] == 'RSA':
        return _original_encrypt_key(key)
    ephemeral = ECC.generate(curve='P-256')
    public = ECC.import_key(read('keys', 'ecdh_public.json'))
    secret = key_agreement(eph_priv=ephemeral, static_pub=public, kdf=lambda x: SHA256.new(x).digest())
    cipher = AES.new(secret, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return {'public':ephemeral.public_key().export_key(format='PEM'), 'nonce':cipher.nonce.hex(),
            'tag':tag.hex(), 'ciphertext':ciphertext.hex()}


def rsa_decrypt_key(ciphertext):
    if ALGORITHMS['key'] == 'RSA':
        return _original_decrypt_key(ciphertext)
    private = ECC.import_key(read('keys','ecdh_private.json'))
    public = ECC.import_key(ciphertext['public'])
    secret = key_agreement(static_priv=private, eph_pub=public, kdf=lambda x: SHA256.new(x).digest())
    cipher = AES.new(secret, AES.MODE_EAX, nonce=bytes.fromhex(ciphertext['nonce']))
    return cipher.decrypt_and_verify(bytes.fromhex(ciphertext['ciphertext']), bytes.fromhex(ciphertext['tag']))


def generate_signing_keys():
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_generate_signing_keys()
    if ALGORITHMS['signature'] == 'RSA':
        key = RSA.generate(ALGORITHMS['rsa_bits']['signature'])
        return key.export_key(), {'pem':key.publickey().export_key().decode()}
    group = read('keys','schnorr.json')
    private = secrets.randbelow(group['q']-1)+1
    return private, {**group, 'y':pow(group['g'],private,group['p'])}


def schnorr_challenge(digest, commitment, public):
    message = json.dumps([digest, commitment, public['p'], public['q'], public['g'], public['y']], separators=(',', ':'))
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % public['q']


def sign_hash(digest, private, public):
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_sign_hash(digest, private, public)
    if ALGORITHMS['signature'] == 'RSA':
        return pkcs1_15.new(RSA.import_key(private)).sign(SHA256.new(bytes.fromhex(digest))).hex()
    nonce = secrets.randbelow(public['q']-1)+1
    commitment = pow(public['g'],nonce,public['p'])
    challenge = schnorr_challenge(digest,commitment,public)
    return [challenge, (nonce+private*challenge) % public['q']]


def signature_values(digest, signature, public):
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_signature_values(digest, signature, public)
    if ALGORITHMS['signature'] == 'RSA':
        key = RSA.import_key(public['pem'])
        # PKCS#1 v1.5 SHA-256 DigestInfo, signing the selected document digest.
        info = bytes.fromhex('3031300d060960864801650304020105000420') + SHA256.new(bytes.fromhex(digest)).digest()
        size = key.size_in_bytes()
        expected = b'\x00\x01' + b'\xff'*(size-len(info)-3) + b'\x00' + info
        data = bytes.fromhex(signature)
        value = int.from_bytes(data,'big')
        if len(data) != size or value >= key.n:
            return expected.hex(), 'INVALID SIGNATURE'
        return expected.hex(), pow(value,key.e,key.n).to_bytes(size,'big').hex()
    challenge, response = signature
    if not (0 <= challenge < public['q'] and 0 <= response < public['q']):
        return 'VALID RANGE', 'INVALID SIGNATURE'
    commitment = pow(public['g'],response,public['p']) * pow(pow(public['y'],challenge,public['p']),-1,public['p']) % public['p']
    return challenge, schnorr_challenge(digest,commitment,public)


def search_token(value):
    if ALGORITHMS['search'] == 'SSE':
        return _original_search_token(value)
    return hashlib.sha256(value.encode()).hexdigest()


def index_token(value):
    token = search_token(value)
    if ALGORITHMS['search'] == 'SSE':
        return token
    public = RSA.import_key(read('keys','search_public.json'))
    return PKCS1_OAEP.new(public,hashAlgo=SHA256).encrypt(bytes.fromhex(token)).hex()


def stored_search_token(token):
    if ALGORITHMS['search'] == 'SSE':
        return token
    private = RSA.import_key(read('keys','search_private.json'))
    return PKCS1_OAEP.new(private,hashAlgo=SHA256).decrypt(bytes.fromhex(token)).hex()


def indexes_match(stored, expected):
    return set(stored) == set(expected) and all(hmac.compare_digest(stored_search_token(stored[k]), stored_search_token(expected[k])) for k in stored)

from decimal import Decimal, InvalidOperation


def record_filename(record_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", record_id):
        raise ValueError("Record ID must contain 1..40 letters, digits, underscores or hyphens.")
    return record_id + ".json"


def require(action):
    if ROLE not in ENTITIES or action not in ENTITIES[ROLE]:
        raise PermissionError("This entity cannot perform " + action)


def normalize_record(values):
    if set(values) != {field["name"] for field in DOMAIN["fields"]}:
        raise ValueError("Record fields do not match the configured schema.")
    result = {}
    for field in DOMAIN["fields"]:
        name, kind = field["name"], field["type"]
        value = str(values[name]).strip()
        if not value:
            raise ValueError(name + " cannot be empty.")
        if kind == "text":
            result[name] = value
        elif kind == "choice":
            matches = [option for option in field["choices"] if option.casefold() == value.casefold()]
            if not matches:
                raise ValueError(name + ": choose " + ", ".join(field["choices"]))
            result[name] = matches[0]
        else:
            if len(value) > 80 or not re.fullmatch(r"[+]?[0-9]+(?:[.][0-9]+)?", value):
                raise ValueError(name + ": use nonnegative digits with an optional decimal point (no exponent notation).")
            try:
                number = Decimal(value)
                scale = field.get("decimals", 0)
                if not number.is_finite() or number < 0 or number > Decimal(10**18) / (10**scale):
                    raise ValueError(name + ": use a finite nonnegative number within the allowed range.")
                units = number * (10**scale)
                if units != units.to_integral_value():
                    raise ValueError(name + f": use at most {scale} decimal places.")
                result[name] = int(number) if kind == "integer" else format(number, f".{scale}f")
            except InvalidOperation as exc:
                raise ValueError(name + ": invalid number.") from exc
    return result


def metric_values(record):
    values = {}
    for name, metric in METRICS.items():
        if metric["kind"] == "record_count":
            values[name] = 1
        elif metric["kind"] == "count":
            values[name] = int(record[metric["field"]] == metric["choice"])
        else:
            values[name] = int(Decimal(str(record[metric["field"]])) * metric["scale"])
    return values


def make_index(record, timestamp):
    result = {field["name"]: index_token(field["name"] + ":" + str(record[field["name"]]).casefold())
              for field in DOMAIN["fields"] if field["search"]}
    result["__minute__"] = index_token("minute:" + timestamp[:16])
    return result


def record_files(filename):
    return {folder: read(folder, filename) for folder in (
        "encrypted", "encrypted_key", "iv", "hashes", "signature",
        "public_key", "paillier", "metadata", "index")}


def valid_receipt(filename):
    return hmac.compare_digest(read("receipts", filename), seal(record_files(filename)))


def submit_record(record_id, values):
    require("submit_record")
    EVENTS.clear()
    filename = record_filename(record_id)
    if (BASE / "metadata" / filename).exists():
        raise ValueError("Record ID already exists; use a new ID for a new record.")
    if DOMAIN["close_on_aggregate"] and (BASE / "tally" / "aggregate.json").exists():
        raise ValueError("Submissions closed when the aggregate was created.")
    record = normalize_record(values)
    serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
    digest = timed("Hashing", hash_message, serialized)
    private_key, public_key = generate_signing_keys()
    signature = timed("Signing", sign_hash, digest, private_key, public_key)
    n = read("keys", "paillier_public.json")["n"]
    encrypted, randomness = {}, {}
    for name, value in metric_values(record).items():
        encrypted[name], randomness[name] = timed("Paillier encryption", paillier_encrypt, value, n)
    payload = json.dumps({"record": record, "randomness": randomness}, ensure_ascii=False)
    key = document_key()
    iv, ciphertext = timed(ALGORITHMS["encryption"] + " encryption", aes_encrypt, payload, key)
    wrapped = timed(ALGORITHMS["key"] + " key encryption", rsa_encrypt_key, key)
    timestamp = now()
    settings = read("keys", "settings.json")
    if not settings["start"] <= timestamp <= settings["deadline"]:
        raise ValueError("Outside the submission period.")
    files = {"encrypted": ciphertext, "encrypted_key": wrapped, "iv": iv,
             "hashes": digest, "signature": signature, "public_key": public_key,
             "paillier": encrypted, "metadata": {"submitted_at": timestamp},
             "index": make_index(record, timestamp)}
    for folder, value in files.items():
        save(folder, filename, value)
    save("receipts", filename, seal(record_files(filename)))
    show_summary("Submit " + DOMAIN["record_name"], {"Record ID": record_id,
        ALGORITHMS["hash"]: digest, ALGORITHMS["signature"] + " signature": signature, "IV": iv,
        ALGORITHMS["encryption"] + " ciphertext": ciphertext, ALGORITHMS["key"] + "-wrapped key": wrapped,
        "Encrypted totals": encrypted, "Submitted at IST": timestamp, "Result": "SUBMITTED"})
    return True


def check_record(record_id):
    # Internal verification pipeline; exposed only through permission-checked functions.
    filename = record_filename(record_id)
    if not valid_receipt(filename):
        raise ValueError("Receipt mismatch: stored record or metadata was changed.")
    stored_hash = read("hashes", filename)
    signature = read("signature", filename)
    public_key = read("public_key", filename)
    key = timed(ALGORITHMS["key"] + " key decryption", rsa_decrypt_key, read("encrypted_key", filename))
    payload = json.loads(timed(ALGORITHMS["encryption"] + " decryption", aes_decrypt, read("encrypted", filename), key, read("iv", filename)))
    record = normalize_record(payload["record"])
    serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
    computed_hash = timed("Hashing", hash_message, serialized)
    hash_valid = timed("Hash verification", hmac.compare_digest, stored_hash, computed_hash)
    signature_valid = timed("Signature verification", verify_signature, computed_hash, signature, public_key)
    expected, actual = signature_values(computed_hash, signature, public_key)
    timestamp = read("metadata", filename)["submitted_at"]
    datetime.strptime(timestamp, TIME_FORMAT)
    settings = read("keys", "settings.json")
    valid_time = settings["start"] <= timestamp <= settings["deadline"] and timestamp <= now()
    details = {"Record ID": record_id, "Stored " + ALGORITHMS["hash"]: stored_hash, "Computed " + ALGORITHMS["hash"]: computed_hash,
               "Hash comparison": "MATCH" if hash_valid else "MISMATCH", ALGORITHMS["signature"] + " signature": signature,
               "Expected verification value": expected, "Actual verification value": actual,
               "Signature comparison": "MATCH" if signature_valid else "MISMATCH", "Timestamp valid": valid_time}
    if not (hash_valid and signature_valid and valid_time):
        show_summary("Verify " + DOMAIN["record_name"], {**details, "Result": "REJECTED"})
        raise ValueError("Verification failed.")
    n = read("keys", "paillier_public.json")["n"]
    encrypted = read("paillier", filename)
    if set(encrypted) != set(METRICS) or set(payload["randomness"]) != set(METRICS):
        raise ValueError("Encrypted metric schema mismatch.")
    for name, value in metric_values(record).items():
        r = payload["randomness"][name]
        if not 0 < r < n or gcd(r, n) != 1:
            raise ValueError("Invalid Paillier randomness.")
        if encrypted[name] != pow(n + 1, value, n*n) * pow(r, n, n*n) % (n*n):
            raise ValueError("Encrypted total does not match the signed record.")
    if not indexes_match(read("index", filename), make_index(record, timestamp)):
        raise ValueError("Search index mismatch.")
    return record, details


def verify_record(record_id):
    require("verify_record")
    EVENTS.clear()
    _, details = check_record(record_id)
    filename = record_filename(record_id)
    save("verified", filename, {"verified_at": now(), "receipt": read("receipts", filename)})
    show_summary("Verify " + DOMAIN["record_name"], {**details, "Result": "ACCEPTED"})
    return True


def view_record(record_id):
    require("view_record")
    EVENTS.clear()
    record, details = check_record(record_id)
    show_summary("Read " + DOMAIN["record_name"], {**details, "Result": "Verified before display"})
    print("Plaintext record:")
    for field in DOMAIN["fields"]:
        print(field["name"] + ":", record[field["name"]])
    return record


def find_records(field_name=None, query=None, start=None, end=None):
    require("search_records")
    EVENTS.clear()
    tokens = set()
    if field_name is not None:
        field = next((f for f in DOMAIN["fields"] if f["name"] == field_name and f["search"]), None)
        if field is None:
            raise ValueError("This field is not searchable.")
        if field["type"] == "integer":
            query = str(int(query))
        elif field["type"] == "decimal":
            number = Decimal(str(query))
            if not number.is_finite() or number * 10**field["decimals"] != (number * 10**field["decimals"]).to_integral_value():
                raise ValueError("Invalid decimal query precision.")
            query = format(number, f".{field['decimals']}f")
        tokens.add(search_token(field_name + ":" + str(query).strip().casefold()))
        index_field = field_name
    else:
        start_time = datetime.strptime(start, TIME_FORMAT)
        end_time = datetime.strptime(end, TIME_FORMAT)
        if end_time < start_time or end_time - start_time > timedelta(days=7):
            raise ValueError("Use an ordered time range of at most seven days.")
        minute = start_time.replace(second=0)
        while minute <= end_time:
            tokens.add(search_token("minute:" + minute.strftime("%Y-%m-%d %H:%M")))
            minute += timedelta(minutes=1)
        index_field = "__minute__"
    matches = []
    for file in sorted((BASE / "index").glob("*.json")):
        if not valid_receipt(file.name):
            continue
        if stored_search_token(read("index", file.name).get(index_field)) not in tokens:
            continue
        if field_name is None:
            timestamp = datetime.strptime(read("metadata", file.name)["submitted_at"], TIME_FORMAT)
            if not start_time <= timestamp <= end_time:
                continue
        matches.append(file.stem)
    show_summary("Search", {"Matching record IDs": matches})
    return matches


def search_records():
    require("search_records")
    fields = [f for f in DOMAIN["fields"] if f["search"]]
    for number, field in enumerate(fields, 1):
        print(f"{number}. {field['name']}")
    print(f"{len(fields)+1}. Submission time range")
    choice = int(input("Search by: "))
    if 1 <= choice <= len(fields):
        field = fields[choice-1]
        return find_records(field["name"], input("Exact value: "))
    if choice == len(fields)+1:
        print("Use YYYY-MM-DD HH:MM:SS, IST.")
        return find_records(start=input("Start: ").strip(), end=input("End: ").strip())
    raise ValueError("Invalid search selection.")


def build_aggregate():
    n = read("keys", "paillier_public.json")["n"]
    totals = {name: 1 for name in METRICS}
    receipts = {}
    for file in sorted((BASE / "verified").glob("*.json")):
        if not valid_receipt(file.name):
            raise ValueError("Accepted record changed: " + file.stem)
        receipt = read("receipts", file.name)
        if read("verified", file.name)["receipt"] != receipt:
            raise ValueError("Record must be verified again.")
        receipts[file.stem] = receipt
        encrypted = read("paillier", file.name)
        if set(encrypted) != set(METRICS):
            raise ValueError("Metric schema mismatch.")
        for name in METRICS:
            totals[name] = totals[name] * encrypted[name] % (n*n)
    count = len(receipts)
    if count < DOMAIN["min_records"]:
        raise ValueError(f"Verify at least {DOMAIN['min_records']} records first.")
    if count != len(list((BASE / "receipts").glob("*.json"))):
        raise ValueError("Every submitted record must be verified before aggregation.")
    if count * 10**18 >= n:
        raise ValueError("Aggregate could overflow the Paillier plaintext range.")
    return {"ciphertexts": totals, "records": receipts}


def aggregate_records():
    require("aggregate_records")
    EVENTS.clear()
    aggregate = timed("Homomorphic aggregation", build_aggregate)
    save("tally", "aggregate.json", aggregate)
    save("tally", "aggregate_seal.json", seal(aggregate))
    show_summary("Aggregate", {"Included record IDs": list(aggregate["records"]),
                              "Encrypted totals": aggregate["ciphertexts"],
                              "Submissions closed": DOMAIN["close_on_aggregate"]})
    return aggregate


def threshold_decrypt():
    require("threshold_decrypt")
    EVENTS.clear()
    aggregate = read("tally", "aggregate.json")
    aggregate_seal = read("tally", "aggregate_seal.json")
    if not hmac.compare_digest(seal(aggregate), aggregate_seal):
        raise ValueError("Aggregate was changed.")
    if aggregate != build_aggregate():
        raise ValueError("Aggregate is stale. Re-aggregate all verified records.")
    n = read("keys", "paillier_public.json")["n"]
    partials = []
    for number in (1, 2):
        share = timed(f"Authority {number} authentication", unlock_share, number,
                      getpass(f"Authority {number} password: "))
        partial = {name: timed(f"Authority {number} partial decryption", pow, value, share, n*n)
                   for name, value in aggregate["ciphertexts"].items()}
        save("tally", f"partial_{number}.json", {"created_at": now(), "aggregate_seal": aggregate_seal, "values": partial})
        partials.append(partial)
        del share
    raw_results, results = {}, {}
    for name, metric in METRICS.items():
        combined = partials[0][name] * partials[1][name] % (n*n)
        if (combined-1) % n:
            raise ValueError("Invalid combined partial decryption.")
        value = ((combined-1)//n) % n
        raw_results[name] = value
        results[metric["label"]] = (format(Decimal(value) / metric["scale"], f".{metric['decimals']}f")
                                   if metric["scale"] != 1 else value)
    if raw_results["record_count"] != len(aggregate["records"]):
        raise ValueError("Aggregate record count mismatch.")
    for field in DOMAIN["fields"]:
        names = [name for name, metric in METRICS.items() if metric.get("field") == field["name"] and metric["kind"] == "count"]
        if names and sum(raw_results[name] for name in names) != len(aggregate["records"]):
            raise ValueError("Category count mismatch.")
    save("tally", "final_totals.json", {"completed_at": now(), "results": results})
    show_summary("Threshold decrypt aggregate", results)
    return results


def entity_menu(entity):
    if ROLE != entity:
        raise PermissionError("Wrong entity session.")
    while True:
        print("\n------ " + entity + " ------")
        print("Workflow:", " -> ".join(ENTITIES[entity]) or "none")
        print("1. Run workflow\n2. Back")
        choice = input("Enter choice: ").strip()
        if choice == "2":
            return
        if choice != "1":
            print("Invalid choice.")
            continue
        selected = ENTITIES[entity]
        record_id = None
        if any(action in selected for action in ("submit_record", "verify_record", "view_record")):
            record_id = input(DOMAIN["record_name"] + " ID: ").strip()
            record_filename(record_id)
        for action in DOMAIN_ACTIONS:
            if action not in selected:
                continue
            if action == "submit_record":
                values = {}
                for field in DOMAIN["fields"]:
                    suffix = " (" + ", ".join(field["choices"]) + ")" if field["type"] == "choice" else ""
                    values[field["name"]] = input(field["name"] + suffix + ": ")
                submit_record(record_id, values)
            elif action == "verify_record":
                verify_record(record_id)
            elif action == "view_record":
                view_record(record_id)
            elif action == "search_records":
                search_records()
            elif action == "aggregate_records":
                aggregate_records()
            elif action == "threshold_decrypt":
                threshold_decrypt()


def main():
    global ROLE
    setup()
    names = list(ENTITIES)
    while True:
        print("\n" + DOMAIN["title"])
        for number, name in enumerate(names, 1):
            print(f"{number}. {name}")
        print(f"{len(names)+1}. Exit")
        choice = input("Enter choice: ").strip()
        if choice == str(len(names)+1):
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            print("Invalid choice.")
            continue
        entity = names[int(choice)-1]
        try:
            if login(entity):
                ROLE = entity
                entity_menu(entity)
        except (OSError, ValueError, KeyError, TypeError, IndexError, PermissionError, InvalidOperation) as error:
            print("Workflow stopped:", error)
        finally:
            ROLE = None


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nProgram closed.")
