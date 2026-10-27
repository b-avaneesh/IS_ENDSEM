import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONFIGURATION
# ============================================================

RSA_KEY_SIZE = 2048
ECC_CURVE = ec.SECP256R1()

FILE_SIZES = {
    "1 MB": 1 * 1024 * 1024,
    "10 MB": 10 * 1024 * 1024
}


# ============================================================
# RSA KEY GENERATION
# ============================================================

def generate_rsa_keys():

    start = time.perf_counter()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    public_key = private_key.public_key()

    end = time.perf_counter()

    return private_key, public_key, end - start


# ============================================================
# ECC KEY GENERATION
# ============================================================

def generate_ecc_keys():

    start = time.perf_counter()

    private_key = ec.generate_private_key(ECC_CURVE)
    public_key = private_key.public_key()

    end = time.perf_counter()

    return private_key, public_key, end - start


# ============================================================
# RSA - PROTECT AES KEY
# ============================================================

def rsa_encrypt_key(aes_key, public_key):

    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_key(encrypted_key, private_key):

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ============================================================
# ECC - DERIVE SHARED AES KEY
# ============================================================

def derive_ecc_aes_key(private_key, public_key):

    shared_secret = private_key.exchange(
        ec.ECDH(),
        public_key
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Secure File Transfer"
    ).derive(shared_secret)

    return aes_key


# ============================================================
# AES-GCM FILE ENCRYPTION
# ============================================================

def encrypt_file(data, aes_key):

    nonce = os.urandom(12)

    aes = AESGCM(aes_key)

    ciphertext = aes.encrypt(
        nonce,
        data,
        None
    )

    return nonce, ciphertext


# ============================================================
# AES-GCM FILE DECRYPTION
# ============================================================

def decrypt_file(nonce, ciphertext, aes_key):

    aes = AESGCM(aes_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext


# ============================================================
# RSA FILE TRANSFER TEST
# ============================================================

def test_rsa(data, private_key, public_key):

    # Generate AES key
    aes_key = AESGCM.generate_key(bit_length=256)

    # RSA encrypt AES key
    start = time.perf_counter()

    encrypted_aes_key = rsa_encrypt_key(
        aes_key,
        public_key
    )

    rsa_key_encryption_time = time.perf_counter() - start

    # AES encrypt file
    start = time.perf_counter()

    nonce, ciphertext = encrypt_file(
        data,
        aes_key
    )

    encryption_time = time.perf_counter() - start

    # RSA decrypt AES key
    start = time.perf_counter()

    decrypted_aes_key = rsa_decrypt_key(
        encrypted_aes_key,
        private_key
    )

    rsa_key_decryption_time = time.perf_counter() - start

    # AES decrypt file
    start = time.perf_counter()

    decrypted_data = decrypt_file(
        nonce,
        ciphertext,
        decrypted_aes_key
    )

    decryption_time = time.perf_counter() - start

    return {
        "key_encryption": rsa_key_encryption_time,
        "key_decryption": rsa_key_decryption_time,
        "encryption": encryption_time,
        "decryption": decryption_time,
        "correct": data == decrypted_data
    }


# ============================================================
# ECC FILE TRANSFER TEST
# ============================================================

def test_ecc(data, sender_private, sender_public,
             receiver_private, receiver_public):

    # Sender derives AES key using:
    # sender private + receiver public

    start = time.perf_counter()

    sender_aes_key = derive_ecc_aes_key(
        sender_private,
        receiver_public
    )

    key_generation_time = time.perf_counter() - start

    # Receiver derives the same AES key using:
    # receiver private + sender public

    receiver_aes_key = derive_ecc_aes_key(
        receiver_private,
        sender_public
    )

    # AES encrypt file
    start = time.perf_counter()

    nonce, ciphertext = encrypt_file(
        data,
        sender_aes_key
    )

    encryption_time = time.perf_counter() - start

    # AES decrypt file
    start = time.perf_counter()

    decrypted_data = decrypt_file(
        nonce,
        ciphertext,
        receiver_aes_key
    )

    decryption_time = time.perf_counter() - start

    return {
        "key_generation": key_generation_time,
        "encryption": encryption_time,
        "decryption": decryption_time,
        "correct": data == decrypted_data,
        "same_key": sender_aes_key == receiver_aes_key
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print("        RSA-2048 vs ECC secp256r1")
    print("           Secure File Transfer")
    print("=" * 65)

    # --------------------------------------------------------
    # Generate RSA keys
    # --------------------------------------------------------

    rsa_private, rsa_public, rsa_keygen_time = generate_rsa_keys()

    # --------------------------------------------------------
    # Generate ECC keys for sender
    # --------------------------------------------------------

    ecc_sender_private, ecc_sender_public, ecc_sender_keygen_time = \
        generate_ecc_keys()

    # --------------------------------------------------------
    # Generate ECC keys for receiver
    # --------------------------------------------------------

    ecc_receiver_private, ecc_receiver_public, ecc_receiver_keygen_time = \
        generate_ecc_keys()

    print("\nKEY GENERATION")
    print("-" * 65)

    print("RSA-2048 key generation time:",
          f"{rsa_keygen_time:.6f} seconds")

    print("ECC secp256r1 sender key generation:",
          f"{ecc_sender_keygen_time:.6f} seconds")

    print("ECC secp256r1 receiver key generation:",
          f"{ecc_receiver_keygen_time:.6f} seconds")

    # --------------------------------------------------------
    # Test different file sizes
    # --------------------------------------------------------

    for size_name, size in FILE_SIZES.items():

        print("\n" + "=" * 65)
        print(f"FILE SIZE: {size_name}")
        print("=" * 65)

        # Generate test file data
        data = os.urandom(size)

        # ----------------------------------------------------
        # RSA TEST
        # ----------------------------------------------------

        rsa_result = test_rsa(
            data,
            rsa_private,
            rsa_public
        )

        # ----------------------------------------------------
        # ECC TEST
        # ----------------------------------------------------

        ecc_result = test_ecc(
            data,
            ecc_sender_private,
            ecc_sender_public,
            ecc_receiver_private,
            ecc_receiver_public
        )

        # ----------------------------------------------------
        # Display RSA results
        # ----------------------------------------------------

        print("\nRSA-2048")
        print("-" * 30)

        print("AES key encryption time :",
              f"{rsa_result['key_encryption']:.6f} s")

        print("File encryption time    :",
              f"{rsa_result['encryption']:.6f} s")

        print("AES key decryption time :",
              f"{rsa_result['key_decryption']:.6f} s")

        print("File decryption time    :",
              f"{rsa_result['decryption']:.6f} s")

        print("Verification             :",
              rsa_result["correct"])

        # ----------------------------------------------------
        # Display ECC results
        # ----------------------------------------------------

        print("\nECC secp256r1")
        print("-" * 30)

        print("ECDH + HKDF key time    :",
              f"{ecc_result['key_generation']:.6f} s")

        print("File encryption time    :",
              f"{ecc_result['encryption']:.6f} s")

        print("File decryption time    :",
              f"{ecc_result['decryption']:.6f} s")

        print("Shared AES key same     :",
              ecc_result["same_key"])

        print("Verification             :",
              ecc_result["correct"])


main()