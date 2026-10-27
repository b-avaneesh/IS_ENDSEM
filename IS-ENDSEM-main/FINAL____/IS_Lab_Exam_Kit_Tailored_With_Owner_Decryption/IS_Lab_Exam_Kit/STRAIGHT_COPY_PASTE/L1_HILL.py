"""2x2 Hill cipher - copy this complete file."""


def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def inverse_key(key):
    a, b = key[0]
    c, d = key[1]
    inverse_det = pow((a * d - b * c) % 26, -1, 26)
    return [[d * inverse_det % 26, -b * inverse_det % 26],
            [-c * inverse_det % 26, a * inverse_det % 26]]


def encrypt_data(data, key):
    data = clean(data)
    if len(data) % 2:
        data += "X"
    answer = ""
    for i in range(0, len(data), 2):
        x, y = ord(data[i]) - 65, ord(data[i + 1]) - 65
        answer += chr((key[0][0] * x + key[0][1] * y) % 26 + 65)
        answer += chr((key[1][0] * x + key[1][1] * y) % 26 + 65)
    return answer


def decrypt_data(encrypted_data, key):
    return encrypt_data(encrypted_data, inverse_key(key))


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    values = list(map(int, input("Enter 4 key values: ").split()))
    key = [[values[0], values[1]], [values[2], values[3]]]
    encrypted = encrypt_data(data, key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, key))

