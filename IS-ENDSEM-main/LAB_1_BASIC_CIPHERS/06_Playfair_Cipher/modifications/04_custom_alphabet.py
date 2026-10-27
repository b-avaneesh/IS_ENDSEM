def create_matrix(key, alphabet):
    key = key.upper()
    alphabet = alphabet.upper()

    sequence = ""

    for ch in key:
        if ch in alphabet and ch not in sequence:
            sequence += ch

    for ch in alphabet:
        if ch not in sequence:
            sequence += ch

    matrix = []

    for i in range(0, 25, 5):
        matrix.append(list(sequence[i:i+5]))

    return matrix


key = input("Enter key: ")

alphabet = input(
    "Enter 25-character alphabet "
    "(example: ABCDEFGHIKLMNOPQRSTUVWXYZ): "
)

matrix = create_matrix(key, alphabet)

print("\nPlayfair Matrix:")

for row in matrix:
    print(" ".join(row))