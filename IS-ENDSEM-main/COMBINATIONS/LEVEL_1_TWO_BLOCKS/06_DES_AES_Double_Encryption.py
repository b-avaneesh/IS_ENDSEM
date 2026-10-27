# A company uses two symmetric algorithms sequentially for protecting confidential data:
#
# Plaintext
#    ↓
# DES
#    ↓
# AES-128
#    ↓
# Final Ciphertext
#
# Write a program that:
#
# Takes plaintext from the user.
# DES-encrypts it using A1B2C3D4.
# AES-128 encrypts the DES ciphertext.
# Displays the intermediate DES ciphertext in HEX.
# Displays final AES ciphertext in HEX.
# Performs reverse decryption.
# Verifies the original plaintext.
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad


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

    des_cipher = des_encrypt(plaintext)

    aes_cipher = aes_encrypt(des_cipher)

    aes_pt = aes_decrypt(aes_cipher)

    des_pt = des_decrypt(aes_pt)
    print("DES cipher: ", des_cipher)
    print("AES cipher: ", aes_cipher)
    print("DES pt: ", des_pt)
    print("AES pt: ", aes_pt)
    print("FINAL PT: ")
    print(des_pt)
    print("Verification:", des_pt == plaintext)
main()