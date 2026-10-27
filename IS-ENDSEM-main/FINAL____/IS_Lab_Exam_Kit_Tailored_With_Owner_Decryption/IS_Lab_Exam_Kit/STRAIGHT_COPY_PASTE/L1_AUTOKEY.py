"""Numeric autokey cipher - copy this complete file."""


def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def encrypt_data(data, key):
    numbers = [ord(ch) - 65 for ch in clean(data)]
    key_stream = [key % 26] + numbers[:-1]
    return "".join(chr((value + key_stream[i]) % 26 + 65) for i, value in enumerate(numbers))


def decrypt_data(encrypted_data, key):
    recovered = []
    for i, ch in enumerate(clean(encrypted_data)):
        current_key = key % 26 if i == 0 else recovered[i - 1]
        recovered.append((ord(ch) - 65 - current_key) % 26)
    return "".join(chr(value + 65) for value in recovered)


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = int(input("Enter numeric key: "))
    encrypted = encrypt_data(data, key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, key))

