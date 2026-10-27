# A system wants to compare how AES modes affect the encryption of a classical-cipher output.
#
# For the message:
#
# Life is full of surprises
#
# Apply Vigenère encryption using key "HEALTH".
# Encrypt the Vigenère output using:
# AES-128 ECB
# AES-128 CBC
# AES-128 CTR
# Measure encryption time for each mode.
# Display the ciphertext for each mode.
# Decrypt each ciphertext.
# Apply Vigenère decryption.
# Verify that all three methods recover the original message.
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad


def encrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""

    for i in range(len(text)):
        ch = text[i]

        if ch in alphabet:
            p = alphabet.index(ch)
            k = ord(key[i % len(key)].lower()) - ord('a')

            c = (p + k) % 62

            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""

    for i in range(len(text)):
        ch = text[i]

        if ch in alphabet:
            c = alphabet.index(ch)
            k = ord(key[i % len(key)].lower()) - ord('a')

            p = (c - k) % 62

            result += alphabet[p]
        else:
            result += ch

    return result

def aes_ecb_encrypt(plaintext):

    # AES-128 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # Convert string to bytes
    plaintext = plaintext.encode()

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad plaintext
    padded_text = pad(plaintext, AES.block_size)

    # Encrypt
    start = time.perf_counter_ns()
    ciphertext = cipher.encrypt(padded_text)
    end = time.perf_counter_ns()

    # Display ciphertext in HEX
    return ciphertext.hex(), end-start

def aes_ecb_decrypt(ciphertext_hex):
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )
    # Create cipher again for decryption
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    # Decrypt
    start = time.perf_counter_ns()
    decrypted = cipher.decrypt(ciphertext)
    end = time.perf_counter_ns()

    # Remove padding
    decrypted = unpad(decrypted, AES.block_size)

    # Convert bytes back to string
    return decrypted.decode(), end - start

def aes_cbc_encrypt(plaintext):
    # AES-128 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # AES CBC IV
    iv = bytes.fromhex(
        "00000000000000000000000000000000"
    )

    # Convert string to bytes
    plaintext = plaintext.encode()

    # Create AES-CBC cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad plaintext
    padded_text = pad(plaintext, AES.block_size)

    # Encrypt
    start = time.perf_counter_ns()
    ciphertext = cipher.encrypt(padded_text)
    end = time.perf_counter_ns()

    return ciphertext.hex(), end - start

def aes_cbc_decrypt(ciphertext_hex):
    # AES-128 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # AES CBC IV
    iv = bytes.fromhex(
        "00000000000000000000000000000000"
    )

    # Create cipher again for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = bytes.fromhex(ciphertext_hex)
    # Decrypt
    start = time.perf_counter_ns()
    decrypted = cipher.decrypt(ciphertext)
    end = time.perf_counter_ns()

    # Remove padding
    decrypted = unpad(decrypted, AES.block_size)

    # Convert bytes to string
    return decrypted.decode(), end - start

def aes_ctr_encrypt(plaintext):

    # AES-128 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # 8-byte nonce
    nonce = bytes.fromhex(
        "0000000000000000"
    )


    # Convert string to bytes
    plaintext = plaintext.encode()

    # Create AES-CTR cipher
    cipher = AES.new(
        key,
        AES.MODE_CTR,
        nonce=nonce
    )

    # Encrypt
    start = time.perf_counter_ns()
    ciphertext = cipher.encrypt(plaintext)
    end = time.perf_counter_ns()

    return ciphertext.hex(), end - start

def aes_ctr_decrypt(ciphertext_hex):
    # AES-128 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # 8-byte nonce
    nonce = bytes.fromhex(
        "0000000000000000"
    )

    # Create cipher again for decryption
    cipher = AES.new(
        key,
        AES.MODE_CTR,
        nonce=nonce
    )

    ciphertext = bytes.fromhex(ciphertext_hex)
    # Decrypt
    start = time.perf_counter_ns()
    decrypted = cipher.decrypt(ciphertext)
    end = time.perf_counter_ns()

    return decrypted.decode(), end - start

def main():
    plaintext = "Life is full of surprises"

    # Vigenere encryption
    vig_cipher = encrypt(plaintext, "HEALTH")

    print("Original plaintext:", plaintext)
    print("Vigenere ciphertext:", vig_cipher)

    # AES ECB
    ecb_cipher, ecb_enc_time = aes_ecb_encrypt(vig_cipher)
    ecb_pt, ecb_dec_time = aes_ecb_decrypt(ecb_cipher)

    # AES CBC
    cbc_cipher, cbc_enc_time = aes_cbc_encrypt(vig_cipher)
    cbc_pt, cbc_dec_time = aes_cbc_decrypt(cbc_cipher)

    # AES CTR
    ctr_cipher, ctr_enc_time = aes_ctr_encrypt(vig_cipher)
    ctr_pt, ctr_dec_time = aes_ctr_decrypt(ctr_cipher)

    # Vigenere decryption
    ecb_final = decrypt(ecb_pt, "HEALTH")
    cbc_final = decrypt(cbc_pt, "HEALTH")
    ctr_final = decrypt(ctr_pt, "HEALTH")

    print("\n--- AES ECB ---")
    print("Ciphertext:", ecb_cipher)
    print("Encryption time:", ecb_enc_time, "ns")
    print("Decryption time:", ecb_dec_time, "ns")
    print("Final plaintext:", ecb_final)

    print("\n--- AES CBC ---")
    print("Ciphertext:", cbc_cipher)
    print("Encryption time:", cbc_enc_time, "ns")
    print("Decryption time:", cbc_dec_time, "ns")
    print("Final plaintext:", cbc_final)

    print("\n--- AES CTR ---")
    print("Ciphertext:", ctr_cipher)
    print("Encryption time:", ctr_enc_time, "ns")
    print("Decryption time:", ctr_dec_time, "ns")
    print("Final plaintext:", ctr_final)

    print("\n--- Verification ---")
    print("ECB correct:", ecb_final == plaintext)
    print("CBC correct:", cbc_final == plaintext)
    print("CTR correct:", ctr_final == plaintext)


main()