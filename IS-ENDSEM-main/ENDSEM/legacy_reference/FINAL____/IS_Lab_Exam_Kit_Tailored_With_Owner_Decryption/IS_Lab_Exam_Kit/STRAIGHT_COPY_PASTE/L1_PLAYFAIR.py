"""Playfair cipher - copy this complete file."""


def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha()).replace("J", "I")


def make_matrix(key):
    letters = []
    for ch in clean(key) + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in letters:
            letters.append(ch)
    return [letters[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix, letter):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col


def make_pairs(data, insert_x=True):
    data = clean(data)
    pairs, i = [], 0
    while i < len(data):
        first = data[i]
        second = data[i + 1] if i + 1 < len(data) else "X"
        if insert_x and first == second:
            pairs.append((first, "X"))
            i += 1
        else:
            pairs.append((first, second))
            i += 2
    return pairs


def change_pair(first, second, matrix, direction):
    r1, c1 = find_position(matrix, first)
    r2, c2 = find_position(matrix, second)
    if r1 == r2:
        return matrix[r1][(c1 + direction) % 5] + matrix[r2][(c2 + direction) % 5]
    if c1 == c2:
        return matrix[(r1 + direction) % 5][c1] + matrix[(r2 + direction) % 5][c2]
    return matrix[r1][c2] + matrix[r2][c1]


def encrypt_data(data, key):
    matrix = make_matrix(key)
    return "".join(change_pair(a, b, matrix, 1) for a, b in make_pairs(data))


def decrypt_data(encrypted_data, key):
    matrix = make_matrix(key)
    return "".join(change_pair(a, b, matrix, -1) for a, b in make_pairs(encrypted_data, False))


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter keyword: ")
    encrypted = encrypt_data(data, key)
    print("Matrix:", make_matrix(key))
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, key))

