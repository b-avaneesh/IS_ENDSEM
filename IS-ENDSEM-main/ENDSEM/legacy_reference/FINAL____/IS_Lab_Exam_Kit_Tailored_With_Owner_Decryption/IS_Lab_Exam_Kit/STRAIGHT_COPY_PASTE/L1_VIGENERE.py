"""Vigenere cipher - copy this complete file."""


def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def encrypt_data(data, key):
    data, key = clean(data), clean(key)
    answer = ""
    for i, ch in enumerate(data):
        shift = ord(key[i % len(key)]) - 65
        answer += chr((ord(ch) - 65 + shift) % 26 + 65)
    return answer


def decrypt_data(encrypted_data, key):
    encrypted_data, key = clean(encrypted_data), clean(key)
    answer = ""
    for i, ch in enumerate(encrypted_data):
        shift = ord(key[i % len(key)]) - 65
        answer += chr((ord(ch) - 65 - shift) % 26 + 65)
    return answer


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter keyword: ")
    encrypted = encrypt_data(data, key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, key))

