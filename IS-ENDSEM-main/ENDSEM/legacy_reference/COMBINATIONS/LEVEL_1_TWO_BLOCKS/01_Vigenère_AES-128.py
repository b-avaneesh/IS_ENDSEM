# A secure messaging system first applies Vigenère encryption to a user's message and then encrypts the resulting text using AES-128 in ECB mode.
# Write a Python program that:
#
# Takes plaintext from the user.
# Encrypts it using Vigenère with key "dollars".
# Encrypts the Vigenère ciphertext using AES-128.
# Displays both ciphertexts.
# Performs AES decryption.
# Performs Vigenère decryption.
# Displays the recovered original plaintext.

# Constraints:
#
# Vigenère operates on alphabetic characters.
# Spaces should be preserved.
# AES key: 0123456789ABCDEF0123456789ABCDEF as HEX.

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
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


def aes_encrypt(plaintext):
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
    ciphertext = cipher.encrypt(padded_text)

    return ciphertext.hex()

def aes_decrypt(ciphertext_hex):
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode()

def main():
    plaintext = input("Enter plaintext: ")

    vig_cipher = encrypt(plaintext, "dollars")
    print("Vigenere encryption:", vig_cipher)

    aes_cipher = aes_encrypt(vig_cipher)

    print("AES cipher: ", aes_cipher)

    aes_pt = aes_decrypt(aes_cipher)

    print("AES plaintext: ", aes_pt)

    vig_final_pt = decrypt(aes_pt,"dollars")

    print("Vigenere plaintext: ", vig_final_pt)

main()