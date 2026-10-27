"""LAB 4 - KEY MANAGEMENT AND ACCESS CONTROL

Covers:
1. SecureCorp: RSA + Diffie-Hellman secure communication.
2. HealthCare: Rabin key generation/distribution/revocation/renewal.
3. DigiRights: ElGamal content encryption with access control.
4. Weak RSA factorisation attack.

Requires: pip install pycryptodome
"""

import hashlib
import random
import time
from datetime import datetime, timedelta
from math import gcd

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse


AUDIT_LOG = []
SUBSYSTEMS = {}
FACILITIES = {}
CONTENTS = {}
CONTENT_ACCESS = {}


def log_event(message):
    entry = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - " + message
    AUDIT_LOG.append(entry)
    print(entry)


def show_audit_log():
    for entry in AUDIT_LOG:
        print(entry)


# ===========================================================================
# Q1: SECURECORP - RSA + DIFFIE-HELLMAN
# ===========================================================================
def add_subsystem(name):
    """Scalable: call this function whenever a new subsystem is added."""
    private_key = RSA.generate(2048)
    SUBSYSTEMS[name] = {
        "public_key": private_key.publickey(),
        "private_key": private_key,
        "active": True,
    }
    log_event("RSA keys generated for " + name)


def revoke_subsystem(name):
    if name in SUBSYSTEMS:
        SUBSYSTEMS[name]["active"] = False
        log_event("Keys revoked for " + name)


def renew_subsystem_keys(name):
    if name in SUBSYSTEMS:
        add_subsystem(name)
        log_event("Keys renewed for " + name)


def dh_keypair(p=7919, g=2):
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    return private, public


def rsa_encrypt_number(number, public_key):
    data = str(number).encode()
    return PKCS1_OAEP.new(public_key).encrypt(data)


def rsa_decrypt_number(ciphertext, private_key):
    data = PKCS1_OAEP.new(private_key).decrypt(ciphertext)
    return int(data.decode())


def aes_encrypt_with_secret(plaintext, shared_secret):
    key = hashlib.sha256(str(shared_secret).encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {"nonce": cipher.nonce, "tag": tag, "ciphertext": ciphertext}


def aes_decrypt_with_secret(package, shared_secret):
    key = hashlib.sha256(str(shared_secret).encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX, nonce=package["nonce"])
    return cipher.decrypt_and_verify(package["ciphertext"], package["tag"]).decode()


def secure_communication(sender, receiver, message):
    """RSA protects the DH public values; DH creates the shared AES key."""
    if sender not in SUBSYSTEMS or receiver not in SUBSYSTEMS:
        raise ValueError("Add both subsystems first")
    if not SUBSYSTEMS[sender]["active"] or not SUBSYSTEMS[receiver]["active"]:
        raise PermissionError("A subsystem has revoked keys")

    p, g = 7919, 2
    sender_private, sender_public = dh_keypair(p, g)
    receiver_private, receiver_public = dh_keypair(p, g)

    # Exchange DH public numbers after protecting them using receiver RSA keys.
    protected_sender_public = rsa_encrypt_number(
        sender_public, SUBSYSTEMS[receiver]["public_key"]
    )
    received_sender_public = rsa_decrypt_number(
        protected_sender_public, SUBSYSTEMS[receiver]["private_key"]
    )

    protected_receiver_public = rsa_encrypt_number(
        receiver_public, SUBSYSTEMS[sender]["public_key"]
    )
    received_receiver_public = rsa_decrypt_number(
        protected_receiver_public, SUBSYSTEMS[sender]["private_key"]
    )

    sender_secret = pow(received_receiver_public, sender_private, p)
    receiver_secret = pow(received_sender_public, receiver_private, p)
    package = aes_encrypt_with_secret(message, sender_secret)
    recovered = aes_decrypt_with_secret(package, receiver_secret)
    log_event(sender + " securely sent a message to " + receiver)
    return package, recovered


# ===========================================================================
# Q2: RABIN KEY MANAGEMENT SERVICE
# ===========================================================================
def rabin_generate_keys(bits=1024):
    """Generate p and q where p % 4 == q % 4 == 3."""
    while True:
        p = getPrime(bits // 2)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits // 2)
        if q % 4 == 3 and q != p:
            break
    return p * q, (p, q)  # public n, private (p, q)


def rabin_encrypt(plaintext, public_key):
    """Prefix RB helps select the correct one of Rabin's four roots."""
    message = int.from_bytes(b"RB" + plaintext.encode(), "big")
    if message >= public_key:
        raise ValueError("Message is too large for this key")
    return pow(message, 2, public_key)


def rabin_decrypt(ciphertext, private_key):
    p, q = private_key
    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    yp = inverse(p, q)
    yq = inverse(q, p)
    roots = [
        (yp * p * mq + yq * q * mp) % n,
        (-yp * p * mq - yq * q * mp) % n,
        (yp * p * mq - yq * q * mp) % n,
        (-yp * p * mq + yq * q * mp) % n,
    ]
    for root in roots:
        size = max(1, (root.bit_length() + 7) // 8)
        data = root.to_bytes(size, "big")
        if data.startswith(b"RB"):
            return data[2:].decode()
    raise ValueError("Correct Rabin root not found")


def register_facility(name, bits=1024):
    public_key, private_key = rabin_generate_keys(bits)
    FACILITIES[name] = {
        "public_key": public_key,
        "private_key": private_key,
        "active": True,
        "created": datetime.now(),
    }
    log_event("Rabin keys generated for " + name)


def distribute_facility_keys(name, authorized):
    if not authorized:
        raise PermissionError("Only an authorized user can request keys")
    record = FACILITIES.get(name)
    if not record or not record["active"]:
        raise ValueError("Facility is missing or revoked")
    log_event("Keys distributed to " + name)
    return record["public_key"], record["private_key"]


def revoke_facility(name):
    if name in FACILITIES:
        FACILITIES[name]["active"] = False
        log_event("Rabin keys revoked for " + name)


def renew_facility(name, bits=1024):
    register_facility(name, bits)
    log_event("Rabin keys renewed for " + name)


def renew_keys_older_than(days=365, bits=1024):
    now = datetime.now()
    for name, record in list(FACILITIES.items()):
        if now - record["created"] >= timedelta(days=days):
            renew_facility(name, bits)


def rabin_rsa_tradeoff():
    """Short trade-off answer requested in Question 2."""
    points = [
        "Rabin encryption is fast: c = m^2 mod n.",
        "Rabin security is directly related to integer factorisation.",
        "Rabin decryption produces four roots, so redundancy is needed.",
        "RSA decryption gives one plaintext and is easier to use in practice.",
        "Both require large random primes, padding and protected private keys.",
    ]
    for point in points:
        print("-", point)
    return points


# ===========================================================================
# ADDITIONAL Q1: SIMPLE ELGAMAL DRM + ACCESS CONTROL
# ===========================================================================
def elgamal_master_keys(p=7919, g=2):
    private_key = random.randint(2, p - 2)
    public_key = (p, g, pow(g, private_key, p))
    return public_key, private_key


MASTER_PUBLIC_KEY, MASTER_PRIVATE_KEY = elgamal_master_keys()


def elgamal_encrypt(plaintext, public_key=None):
    if public_key is None:
        public_key = MASTER_PUBLIC_KEY
    p, g, y = public_key
    encrypted = []
    for byte in plaintext.encode():
        k = random.randint(2, p - 2)
        encrypted.append((pow(g, k, p), byte * pow(y, k, p) % p))
    return encrypted


def elgamal_decrypt(ciphertext, private_key=None, p=7919):
    if private_key is None:
        private_key = MASTER_PRIVATE_KEY
    answer = []
    for c1, c2 in ciphertext:
        secret = pow(c1, private_key, p)
        answer.append(c2 * pow(secret, -1, p) % p)
    return bytes(answer).decode()


def upload_content(creator, content_id, plaintext):
    CONTENTS[content_id] = {
        "creator": creator,
        "ciphertext": elgamal_encrypt(plaintext),
    }
    log_event(creator + " uploaded encrypted content " + content_id)


def grant_access(creator, customer, content_id, minutes=60):
    if content_id not in CONTENTS or CONTENTS[content_id]["creator"] != creator:
        raise PermissionError("Only the content creator can grant access")
    CONTENT_ACCESS[(customer, content_id)] = datetime.now() + timedelta(minutes=minutes)
    log_event("Access granted to " + customer + " for " + content_id)


def revoke_access(creator, customer, content_id):
    if content_id not in CONTENTS or CONTENTS[content_id]["creator"] != creator:
        raise PermissionError("Only the content creator can revoke access")
    CONTENT_ACCESS.pop((customer, content_id), None)
    log_event("Access revoked for " + customer + " on " + content_id)


def view_content(customer, content_id):
    expiry = CONTENT_ACCESS.get((customer, content_id))
    if expiry is None or datetime.now() > expiry:
        raise PermissionError("Access is missing or expired")
    return elgamal_decrypt(CONTENTS[content_id]["ciphertext"])


def renew_master_key():
    """Re-encrypt existing content before replacing the master key."""
    global MASTER_PUBLIC_KEY, MASTER_PRIVATE_KEY
    plaintexts = {
        content_id: elgamal_decrypt(item["ciphertext"])
        for content_id, item in CONTENTS.items()
    }
    MASTER_PUBLIC_KEY, MASTER_PRIVATE_KEY = elgamal_master_keys()
    for content_id, plaintext in plaintexts.items():
        CONTENTS[content_id]["ciphertext"] = elgamal_encrypt(plaintext)
    log_event("ElGamal master key renewed and content re-encrypted")


# ===========================================================================
# ADDITIONAL Q2: ATTACK A WEAK RSA KEY
# ===========================================================================
def factor_weak_n(n):
    p = 2
    while p * p <= n:
        if n % p == 0:
            return p, n // p
        p += 1
    raise ValueError("Factors not found")


def rsa_encrypt(plaintext, n, e):
    return [pow(byte, e, n) for byte in plaintext.encode()]


def rsa_decrypt(ciphertext, n, d):
    return bytes(pow(number, d, n) for number in ciphertext).decode()


# ===========================================================================
# STANDARD EXAM INTERFACE - SAME NAMES USED IN EVERY LAB FILE
# ===========================================================================
def generate_keys(algorithm="rabin", **options):
    """Generate keys for the chosen Lab 4 system."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "rabin":
        return rabin_generate_keys(options.get("bits", 1024))
    if algorithm == "elgamal":
        return elgamal_master_keys(options.get("p", 7919), options.get("g", 2))
    if algorithm in ("dh", "diffie-hellman"):
        return dh_keypair(options.get("p", 7919), options.get("g", 2))
    raise ValueError("Unsupported algorithm: " + algorithm)


def encrypt_data(data, key, algorithm="rabin", **options):
    """Common encryption name for Rabin, ElGamal, RSA and DH-derived AES."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "rabin":
        return rabin_encrypt(data, key)
    if algorithm == "elgamal":
        return elgamal_encrypt(data, key)
    if algorithm == "rsa":
        n, e = key
        return rsa_encrypt(data, n, e)
    if algorithm in ("dh-aes", "aes-shared-secret"):
        return aes_encrypt_with_secret(data, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def decrypt_data(encrypted_data, key, algorithm="rabin", **options):
    """Common decryption name for Rabin, ElGamal, RSA and DH-derived AES."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "rabin":
        return rabin_decrypt(encrypted_data, key)
    if algorithm == "elgamal":
        return elgamal_decrypt(encrypted_data, key, options.get("p", 7919))
    if algorithm == "rsa":
        n, d = key
        return rsa_decrypt(encrypted_data, n, d)
    if algorithm in ("dh-aes", "aes-shared-secret"):
        return aes_decrypt_with_secret(encrypted_data, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def hash_data(data, algorithm="sha256"):
    """Common hashing name used by the template and other lab files."""
    raw = data.encode() if isinstance(data, str) else data
    return hashlib.new(algorithm.lower().replace("-", ""), raw).hexdigest()


def demonstrate_rsa_attack(plaintext="SECRET", p=17, q=19, e=5):
    n = p * q
    ciphertext = rsa_encrypt(plaintext, n, e)
    found_p, found_q = factor_weak_n(n)
    phi = (found_p - 1) * (found_q - 1)
    recovered_d = pow(e, -1, phi)
    recovered_text = rsa_decrypt(ciphertext, n, recovered_d)
    return {
        "public_key": (n, e),
        "ciphertext": ciphertext,
        "recovered_factors": (found_p, found_q),
        "recovered_private_d": recovered_d,
        "recovered_plaintext": recovered_text,
    }


def demo():
    print("\nSECURECORP")
    for name in ["Finance", "HR", "Supply Chain"]:
        add_subsystem(name)
    package, recovered = secure_communication("Finance", "HR", "Annual report")
    print("Ciphertext:", package["ciphertext"].hex())
    print("Recovered:", recovered)

    print("\nHEALTHCARE RABIN")
    register_facility("Hospital A", bits=512)  # 1024 in the actual question
    public_key, private_key = distribute_facility_keys("Hospital A", authorized=True)
    encrypted = rabin_encrypt("Patient record", public_key)
    print("Ciphertext:", encrypted)
    print("Recovered:", rabin_decrypt(encrypted, private_key))

    print("\nDRM")
    upload_content("creator1", "movie1", "Protected movie data")
    grant_access("creator1", "customer1", "movie1", minutes=60)
    print(view_content("customer1", "movie1"))

    print("\nWEAK RSA ATTACK")
    print(demonstrate_rsa_attack())


if __name__ == "__main__":
    demo()
