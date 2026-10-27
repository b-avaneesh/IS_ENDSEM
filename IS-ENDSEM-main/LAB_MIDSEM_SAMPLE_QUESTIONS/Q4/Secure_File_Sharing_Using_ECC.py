import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------- ECC KEY GENERATION ----------

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


# ---------- STORE ECC KEYS ----------

def save_private_key(private_key, filename):
    key_data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

    with open(filename, "wb") as f:
        f.write(key_data)


def save_public_key(public_key, filename):
    key_data = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(filename, "wb") as f:
        f.write(key_data)


# ---------- RETRIEVE ECC KEYS ----------

def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ---------- ECDH ----------

def generate_shared_secret(private_key, public_key):
    return private_key.exchange(
        ec.ECDH(),
        public_key
    )


# ---------- HKDF ----------

def derive_aes_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC Secure Transaction"
    ).derive(shared_secret)


# ---------- AES-GCM ENCRYPTION ----------

def encrypt_message(message, aes_key):
    aes = AESGCM(aes_key)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        message.encode(),
        None
    )

    return nonce, ciphertext


# ---------- AES-GCM DECRYPTION ----------

def decrypt_message(nonce, ciphertext, aes_key):
    aes = AESGCM(aes_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()


# ---------- HASH ----------

def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ---------- MAIN ----------

def main():

    os.makedirs("alice", exist_ok=True)
    os.makedirs("bob", exist_ok=True)
    os.makedirs("transfer", exist_ok=True)

    message = input("Enter message: ")

    # =========================
    # ALICE
    # =========================

    alice_private, alice_public = generate_keys()

    save_private_key(
        alice_private,
        "alice/private_key.pem"
    )

    save_public_key(
        alice_public,
        "alice/public_key.pem"
    )


    # =========================
    # BOB
    # =========================

    bob_private, bob_public = generate_keys()

    save_private_key(
        bob_private,
        "bob/private_key.pem"
    )

    save_public_key(
        bob_public,
        "bob/public_key.pem"
    )


    # =========================
    # LOAD KEYS FROM FILE
    # =========================

    alice_private = load_private_key(
        "alice/private_key.pem"
    )

    alice_public = load_public_key(
        "alice/public_key.pem"
    )

    bob_private = load_private_key(
        "bob/private_key.pem"
    )

    bob_public = load_public_key(
        "bob/public_key.pem"
    )


    # =========================
    # ECDH
    # =========================

    alice_secret = generate_shared_secret(
        alice_private,
        bob_public
    )

    bob_secret = generate_shared_secret(
        bob_private,
        alice_public
    )

    print("\nShared Secret Same:",
          alice_secret == bob_secret)


    # =========================
    # DERIVE AES KEY
    # =========================

    alice_aes_key = derive_aes_key(alice_secret)
    bob_aes_key = derive_aes_key(bob_secret)

    print("AES Key Same:",
          alice_aes_key == bob_aes_key)


    # =========================
    # ENCRYPT
    # =========================

    nonce, ciphertext = encrypt_message(
        message,
        alice_aes_key
    )

    # Store nonce
    with open("transfer/nonce.txt", "w") as f:
        f.write(nonce.hex())

    # Store ciphertext
    with open("transfer/ciphertext.txt", "w") as f:
        f.write(ciphertext.hex())

    # Store hash of ciphertext
    hash_value = sha256(ciphertext)

    with open("transfer/hash.txt", "w") as f:
        f.write(hash_value)


    print("\nCiphertext:",
          ciphertext.hex())

    print("Nonce:",
          nonce.hex())

    print("SHA-256:",
          hash_value)


    # =========================
    # BOB RECEIVES FILES
    # =========================

    with open("transfer/nonce.txt", "r") as f:
        nonce = bytes.fromhex(f.read())

    with open("transfer/ciphertext.txt", "r") as f:
        ciphertext = bytes.fromhex(f.read())

    with open("transfer/hash.txt", "r") as f:
        stored_hash = f.read()


    # =========================
    # INTEGRITY CHECK
    # =========================

    received_hash = sha256(ciphertext)

    print("\nIntegrity Check:",
          stored_hash == received_hash)

    if stored_hash != received_hash:
        print("Integrity Failed!")
        return

    print("Integrity Verified!")


    # =========================
    # DECRYPT
    # =========================

    plaintext = decrypt_message(
        nonce,
        ciphertext,
        bob_aes_key
    )

    print("\nDecrypted:",
          plaintext)

    print("Verification:",
          plaintext == message)


if __name__ == "__main__":
    main()