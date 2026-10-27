def create_matrix(key, omitted):
    omitted = omitted.upper()

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    alphabet = alphabet.replace(omitted, "")

    key = key.upper().replace(omitted, "")

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
omitted = input("Enter character to omit (e.g. J): ")

matrix = create_matrix(key, omitted)

print("\nPlayfair Matrix:")

for row in matrix:
    print(" ".join(row))