"""Keyed block transposition - copy this complete file."""


def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def encrypt_data(data, key):
    data = clean(data)
    while len(data) % len(key):
        data += "X"
    answer = ""
    for i in range(0, len(data), len(key)):
        block = data[i:i + len(key)]
        answer += "".join(block[position] for position in key)
    return answer


def decrypt_data(encrypted_data, key):
    encrypted_data = clean(encrypted_data)
    answer = ""
    for i in range(0, len(encrypted_data), len(key)):
        block = encrypted_data[i:i + len(key)]
        original = [""] * len(key)
        for encrypted_position, original_position in enumerate(key):
            original[original_position] = block[encrypted_position]
        answer += "".join(original)
    return answer


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = list(map(int, input("Enter permutation key, e.g. 2 0 1: ").split()))
    encrypted = encrypt_data(data, key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, key))
