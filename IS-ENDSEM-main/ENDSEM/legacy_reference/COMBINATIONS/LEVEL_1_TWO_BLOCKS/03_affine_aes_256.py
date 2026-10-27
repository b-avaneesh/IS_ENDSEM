from math import gcd
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def inverse(k):
    for i in range(26):
        if (k * i) % 26 == 1:
            return i
    return -1


def encrypt(text, k1, k2):
    result = ""

    for ch in text:
        if ch.isupper():
            p = ord(ch) - ord('A')
            c = (p * k1 + k2) % 26
            result += chr(c + ord('A'))

        elif ch.islower():
            p = ord(ch) - ord('a')
            c = (p * k1 + k2) % 26
            result += chr(c + ord('a'))

        else:
            result += ch

    return result


def decrypt(text, k1, k2):
    result = ""
    k1_inverse = inverse(k1)

    for ch in text:
        if ch.isupper():
            c = ord(ch) - ord('A')
            p = ((c - k2) * k1_inverse) % 26
            result += chr(p + ord('A'))

        elif ch.islower():
            c = ord(ch) - ord('a')
            p = ((c - k2) * k1_inverse) % 26
            result += chr(p + ord('a'))

        else:
            result += ch

    return result

def aes_encrypt(plaintext):
    # AES-256 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
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
    # AES-256 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    )

    # Convert HEX string to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt
    padded_text = cipher.decrypt(ciphertext)

    # Remove padding
    plaintext = unpad(padded_text, AES.block_size)

    return plaintext.decode()

def main():
    plaintext = input("Enter plaintext: ")

    affine_cipher = encrypt(plaintext, 15, 20)
    print("Affine encryption:", affine_cipher)

    aes_cipher = aes_encrypt(affine_cipher)

    print("AES cipher: ", aes_cipher)

    aes_pt = aes_decrypt(aes_cipher)

    print("AES plaintext: ", aes_pt)

    affine_final_pt = decrypt(aes_pt,15, 20)

    print("affine plaintext: ", affine_final_pt)

main()