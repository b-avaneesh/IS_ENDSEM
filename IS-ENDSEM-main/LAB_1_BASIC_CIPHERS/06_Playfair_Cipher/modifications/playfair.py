def create_matrix(key):
    key = key.upper().replace('J', 'I')

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    sequence = ""

    # Add key characters
    for ch in key:
        if ch in alphabet and ch not in sequence:
            sequence += ch

    # Add remaining alphabet
    for ch in alphabet:
        if ch not in sequence:
            sequence += ch

    matrix = []

    for i in range(0, 25, 5):
        matrix.append(list(sequence[i:i + 5]))

    return matrix


def find_position(matrix, ch):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == ch:
                return row, col


def prepare_text(text):
    text = text.upper().replace('J', 'I')

    result = ""
    i = 0

    while i < len(text):
        first = text[i]

        if i + 1 < len(text):
            second = text[i + 1]

            if first == second:
                result += first + 'X'
                i += 1
            else:
                result += first + second
                i += 2
        else:
            result += first + 'X'
            i += 1

    return result


def encrypt_pair(a, b, matrix):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Same row
    if r1 == r2:
        return matrix[r1][(c1 + 1) % 5] + \
            matrix[r2][(c2 + 1) % 5]

    # Same column
    elif c1 == c2:
        return matrix[(r1 + 1) % 5][c1] + \
            matrix[(r2 + 1) % 5][c2]

    # Rectangle
    else:
        return matrix[r1][c2] + matrix[r2][c1]


def decrypt_pair(a, b, matrix):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Same row
    if r1 == r2:
        return matrix[r1][(c1 - 1) % 5] + \
            matrix[r2][(c2 - 1) % 5]

    # Same column
    elif c1 == c2:
        return matrix[(r1 - 1) % 5][c1] + \
            matrix[(r2 - 1) % 5][c2]

    # Rectangle
    else:
        return matrix[r1][c2] + matrix[r2][c1]


def encrypt(text, matrix):
    text = prepare_text(text)

    result = ""

    for i in range(0, len(text), 2):
        result += encrypt_pair(text[i], text[i + 1], matrix)

    return result


def decrypt(text, matrix):
    result = ""

    for i in range(0, len(text), 2):
        result += decrypt_pair(text[i], text[i + 1], matrix)

    return result


key = input("Enter key: ")
text = input("Enter plaintext: ")

matrix = create_matrix(key)

print("\nPlayfair Matrix:")

for row in matrix:
    print(" ".join(row))

ciphertext = encrypt(text, matrix)

print("\nPrepared plaintext:", prepare_text(text))
print("Encrypted:", ciphertext)

print("Decrypted:", decrypt(ciphertext, matrix))