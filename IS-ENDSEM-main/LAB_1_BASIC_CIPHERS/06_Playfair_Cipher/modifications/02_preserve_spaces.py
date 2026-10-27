def create_matrix(key):
    key = key.upper().replace('J', 'I')

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    sequence = ""

    for ch in key:
        if ch in alphabet and ch not in sequence:
            sequence += ch

    for ch in alphabet:
        if ch not in sequence:
            sequence += ch

    matrix = []

    for i in range(0, 25, 5):
        matrix.append(list(sequence[i:i + 5]))

    return matrix


def find_position(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c


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

    if r1 == r2:
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]

    elif c1 == c2:
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]

    else:
        return matrix[r1][c2] + matrix[r2][c1]


def encrypt_word(word, matrix):
    prepared = prepare_text(word)

    result = ""

    for i in range(0, len(prepared), 2):
        result += encrypt_pair(prepared[i], prepared[i + 1], matrix)

    return result


key = input("Enter key: ")
text = input("Enter plaintext: ")

matrix = create_matrix(key)

words = text.split()

encrypted_words = []

for word in words:
    encrypted_words.append(encrypt_word(word, matrix))

ciphertext = " ".join(encrypted_words)

print("\nEncrypted:", ciphertext)