"""Additive/Caesar cipher - copy this complete file."""


def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def encrypt_data(data, key):
    return "".join(chr((ord(ch) - 65 + key) % 26 + 65) for ch in clean(data))


def decrypt_data(encrypted_data, key):
    return "".join(chr((ord(ch) - 65 - key) % 26 + 65) for ch in clean(encrypted_data))


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = int(input("Enter key: "))
    encrypted = encrypt_data(data, key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, key))

