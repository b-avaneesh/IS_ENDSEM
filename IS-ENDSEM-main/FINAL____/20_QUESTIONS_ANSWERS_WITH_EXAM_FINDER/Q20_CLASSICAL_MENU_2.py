# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - No EduSecure role-based or modern-cryptography code is needed.
# - Provide Vigenere, autokey, Playfair and Hill encrypt/decrypt choices.
# - Accept the appropriate keyword, numeric key or 2x2 matrix from the user.
# - Display the Playfair matrix and inverse Hill key.
# =====================================================================
"""Vigenere, autokey, Playfair and Hill menu."""

from itertools import permutations

from math import gcd

def clean_text(text):
    """Keep letters only and convert them to uppercase."""
    return "".join(ch.upper() for ch in text if ch.isalpha())

def mod_inverse(number, modulus=26):
    """Return the multiplicative inverse. Example: inverse of 15 mod 26 is 7."""
    if gcd(number, modulus) != 1:
        raise ValueError("Key has no inverse. Choose a key coprime with 26.")
    return pow(number, -1, modulus)

def vigenere_encrypt(plaintext, key):
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    if not key:
        raise ValueError("Key cannot be empty")
    answer = ""
    for i, ch in enumerate(plaintext):
        shift = ord(key[i % len(key)]) - 65
        answer += chr((ord(ch) - 65 + shift) % 26 + 65)
    return answer

def vigenere_decrypt(ciphertext, key):
    ciphertext = clean_text(ciphertext)
    key = clean_text(key)
    if not key:
        raise ValueError("Key cannot be empty")
    answer = ""
    for i, ch in enumerate(ciphertext):
        shift = ord(key[i % len(key)]) - 65
        answer += chr((ord(ch) - 65 - shift) % 26 + 65)
    return answer

def autokey_encrypt(plaintext, first_key):
    plaintext = clean_text(plaintext)
    plain_numbers = [ord(ch) - 65 for ch in plaintext]
    key_stream = [first_key % 26] + plain_numbers[:-1]
    return "".join(chr((p + k) % 26 + 65) for p, k in zip(plain_numbers, key_stream))

def autokey_decrypt(ciphertext, first_key):
    ciphertext = clean_text(ciphertext)
    recovered = []
    for i, ch in enumerate(ciphertext):
        key_value = first_key % 26 if i == 0 else recovered[i - 1]
        recovered.append((ord(ch) - 65 - key_value) % 26)
    return "".join(chr(value + 65) for value in recovered)

def playfair_matrix(key):
    text = clean_text(key).replace("J", "I") + "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    letters = []
    for ch in text:
        if ch not in letters:
            letters.append(ch)
    return [letters[i:i + 5] for i in range(0, 25, 5)]

def playfair_pairs(text, for_encryption=True):
    text = clean_text(text).replace("J", "I")
    pairs = []
    i = 0
    while i < len(text):
        first = text[i]
        second = text[i + 1] if i + 1 < len(text) else "X"
        if for_encryption and first == second:
            second = "X"
            i += 1
        else:
            i += 2
        pairs.append((first, second))
    return pairs

def playfair_position(matrix, letter):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    raise ValueError("Letter not found")

def playfair_encrypt(plaintext, key):
    matrix = playfair_matrix(key)
    answer = ""
    for first, second in playfair_pairs(plaintext):
        r1, c1 = playfair_position(matrix, first)
        r2, c2 = playfair_position(matrix, second)
        if r1 == r2:
            answer += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            answer += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:
            answer += matrix[r1][c2] + matrix[r2][c1]
    return answer

def playfair_decrypt(ciphertext, key):
    matrix = playfair_matrix(key)
    answer = ""
    for first, second in playfair_pairs(ciphertext, for_encryption=False):
        r1, c1 = playfair_position(matrix, first)
        r2, c2 = playfair_position(matrix, second)
        if r1 == r2:
            answer += matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:
            answer += matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
        else:
            answer += matrix[r1][c2] + matrix[r2][c1]
    return answer

def hill_encrypt(plaintext, key):
    text = clean_text(plaintext)
    if len(text) % 2 == 1:
        text += "X"
    answer = ""
    for i in range(0, len(text), 2):
        x, y = ord(text[i]) - 65, ord(text[i + 1]) - 65
        answer += chr((key[0][0] * x + key[0][1] * y) % 26 + 65)
        answer += chr((key[1][0] * x + key[1][1] * y) % 26 + 65)
    return answer

def hill_inverse_key(key):
    a, b = key[0]
    c, d = key[1]
    determinant = (a * d - b * c) % 26
    inverse_det = mod_inverse(determinant)
    return [
        [(d * inverse_det) % 26, (-b * inverse_det) % 26],
        [(-c * inverse_det) % 26, (a * inverse_det) % 26],
    ]

def hill_decrypt(ciphertext, key):
    return hill_encrypt(ciphertext, hill_inverse_key(key))


def main():
    print("1 Vigenere  2 Autokey  3 Playfair  4 Hill")
    choice = input("Choice: "); text = input("Plaintext: ")
    if choice == "1":
        key = input("Keyword: "); encrypted = vigenere_encrypt(text, key); recovered = vigenere_decrypt(encrypted, key)
    elif choice == "2":
        key = int(input("First numeric key: ")); encrypted = autokey_encrypt(text, key); recovered = autokey_decrypt(encrypted, key)
    elif choice == "3":
        key = input("Keyword: "); print("Matrix:", playfair_matrix(key)); encrypted = playfair_encrypt(text, key); recovered = playfair_decrypt(encrypted, key)
    else:
        values = [int(input(label)) for label in ("a: ", "b: ", "c: ", "d: ")]
        key = [values[:2], values[2:]]; print("Inverse key:", hill_inverse_key(key))
        encrypted = hill_encrypt(text, key); recovered = hill_decrypt(encrypted, key)
    print("Encrypted:", encrypted); print("Decrypted:", recovered)


if __name__ == "__main__": main()
