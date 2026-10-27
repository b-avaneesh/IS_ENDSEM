# A secure communication application first encrypts a message using Vigenère, then encrypts the result using DES.
#
# Write a program that:
#
# Takes plaintext.
# Vigenère encrypts it using key "HEALTH".
# DES encrypts the Vigenère ciphertext.
# Measures:
# Vigenère encryption time
# DES encryption time
# DES decryption time
# Vigenère decryption time
# Recovers and displays the original plaintext.



from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import time
vig_enc_time = 0
vig_dec_time = 0
des_enc_time = 0
des_dec_time = 0


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


def des_encrypt(plaintext):
    # DES key
    key = b"A1B2C3D4"

    # Convert string to bytes
    plaintext = plaintext.encode()

    # Create DES cipher
    cipher = DES.new(key, DES.MODE_ECB)

    # Pad plaintext
    padded_text = pad(plaintext, DES.block_size)

    # Encrypt
    start = time.perf_counter_ns()
    ciphertext = cipher.encrypt(padded_text)
    end = time.perf_counter_ns()

    des_enc_time = end - start
    return des_enc_time,ciphertext.hex()

def des_decrypt(ciphertext_hex):
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = b"A1B2C3D4"

    cipher = DES.new(key, DES.MODE_ECB)

    start = time.perf_counter_ns()
    decrypted = cipher.decrypt(ciphertext)
    end = time.perf_counter_ns()

    des_dec_time = end - start

    plaintext = unpad(decrypted, DES.block_size)

    return des_dec_time,plaintext.decode()

def main():
    plaintext = input("Enter plaintext: ")
    start = time.perf_counter_ns()
    vig_cipher = encrypt(plaintext, "HEALTH")
    end = time.perf_counter_ns()

    vig_enc_time = end - start
    print("Vigenere encryption:", vig_cipher)

    des_enc_time,des_cipher = des_encrypt(vig_cipher)

    print("DES cipher: ", des_cipher)

    des_dec_time, des_pt = des_decrypt(des_cipher)

    print("DES plaintext: ", des_pt)
    start = time.perf_counter_ns()
    vig_final_pt = decrypt(des_pt,"HEALTH")
    end = time.perf_counter_ns()

    vig_dec_time = end - start
    print("Vigenere plaintext: ", vig_final_pt)

    print("DES encryption time: ", des_enc_time)
    print("DES decryption time: ", des_dec_time)
    print("Vigenere encryption time: ", vig_enc_time)
    print("Vigenere decryption time: ", vig_dec_time)


main()
