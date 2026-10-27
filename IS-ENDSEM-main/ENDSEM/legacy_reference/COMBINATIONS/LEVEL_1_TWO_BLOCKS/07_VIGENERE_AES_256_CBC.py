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

    # AES-256 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # 16-byte IV
    iv = bytes.fromhex(
        "00000000000000000000000000000000"
    )

    plaintext = plaintext.encode()

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    padded_text = pad(
        plaintext,
        AES.block_size
    )

    ciphertext = cipher.encrypt(padded_text)

    return ciphertext.hex()


def aes_decrypt(ciphertext_hex):

    # AES-256 key
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # Same IV
    iv = bytes.fromhex(
        "00000000000000000000000000000000"
    )

    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    padded_text = cipher.decrypt(ciphertext)

    plaintext = unpad(
        padded_text,
        AES.block_size
    )

    return plaintext.decode()


def main():

    plaintext = input("Enter patient information: ")

    # -------------------------------
    # Vigenere Encryption
    # -------------------------------

    vig_cipher = encrypt(
        plaintext,
        "dollars"
    )

    print("\nVigenere Ciphertext:")
    print(vig_cipher)

    # -------------------------------
    # AES-256 CBC Encryption
    # -------------------------------

    aes_cipher = aes_encrypt(vig_cipher)

    print("\nAES-256 CBC Ciphertext:")
    print(aes_cipher)

    # -------------------------------
    # AES Decryption
    # -------------------------------

    aes_pt = aes_decrypt(aes_cipher)

    print("\nAfter AES Decryption:")
    print(aes_pt)

    # -------------------------------
    # Vigenere Decryption
    # -------------------------------

    final_pt = decrypt(
        aes_pt,
        "dollars"
    )

    print("\nFinal Plaintext:")
    print(final_pt)

    # -------------------------------
    # Verification
    # -------------------------------

    print("\nVerification:")

    if final_pt == plaintext:
        print("Successful - Original plaintext recovered")
    else:
        print("Failed")


main()