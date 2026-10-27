# A communication system uses a two-layer encryption mechanism:
#
# Plaintext → Additive Cipher → DES
#
# The additive cipher uses key 20.
#
# Write a program that:
#
# Accepts a plaintext message.
# Applies additive encryption with key 20.
# Encrypts the resulting message using DES.
# Displays both intermediate and final ciphertext.
# Decrypts the DES ciphertext.
# Applies additive decryption.
# Displays the original plaintext.
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad,pad


def encrypt(text, key):
    result = ""

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    for ch in text:
        if ch in alphabet:
            p = alphabet.index(ch)
            c = (p + key) % 62
            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, key):
    result = ""

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            p = (c - key) % 62
            result += alphabet[p]
        else:
            result += ch

    return result

def des_encrypt(plaintext):
    key = b"A1B2C3D4"

    cipher = DES.new(key, DES.MODE_ECB)

    padded_text = pad(plaintext.encode(), DES.block_size)

    ciphertext = cipher.encrypt(padded_text)

    return ciphertext.hex()

def des_decrypt(ciphertext):
    key = b"A1B2C3D4"

    ciphertext = bytes.fromhex(ciphertext)

    cipher = DES.new(key, DES.MODE_ECB)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        DES.block_size
    )

    return plaintext.decode()

def main():

    plaintext = input("Enter plaintext: ")

    additive_cipher = encrypt(plaintext,20)

    print("Additive cipher: ", additive_cipher)

    des_cipher = des_encrypt(additive_cipher)

    print("Final DES cipher: ", des_cipher)

    des_pt = des_decrypt(des_cipher)

    print("Des decrypted: ", des_pt)

    final_add_pt = decrypt(des_pt,20)

    print("Final plaintext: ", final_add_pt)


main()