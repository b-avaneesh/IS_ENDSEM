"""LAB 1 - BASIC SYMMETRIC CIPHERS

Every cipher has separate encrypt and decrypt functions.
The functions are intentionally small so they can be copied into an exam program.
Only the Python standard library is required.
"""

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


# ---------------------------------------------------------------------------
# Q1(a) ADDITIVE / CAESAR CIPHER
# ---------------------------------------------------------------------------
def additive_encrypt(plaintext, key):
    answer = ""
    for ch in clean_text(plaintext):
        answer += chr((ord(ch) - ord("A") + key) % 26 + ord("A"))
    return answer


def additive_decrypt(ciphertext, key):
    answer = ""
    for ch in clean_text(ciphertext):
        answer += chr((ord(ch) - ord("A") - key) % 26 + ord("A"))
    return answer


def additive_brute_force(ciphertext):
    """Additional exercise: print all 26 possible plaintexts."""
    for key in range(26):
        print("Key", key, ":", additive_decrypt(ciphertext, key))


# ---------------------------------------------------------------------------
# Q1(b) MULTIPLICATIVE CIPHER
# ---------------------------------------------------------------------------
def multiplicative_encrypt(plaintext, key):
    if gcd(key, 26) != 1:
        raise ValueError("Key must be coprime with 26")
    answer = ""
    for ch in clean_text(plaintext):
        value = (ord(ch) - ord("A")) * key
        answer += chr(value % 26 + ord("A"))
    return answer


def multiplicative_decrypt(ciphertext, key):
    inverse = mod_inverse(key)
    answer = ""
    for ch in clean_text(ciphertext):
        value = (ord(ch) - ord("A")) * inverse
        answer += chr(value % 26 + ord("A"))
    return answer


# ---------------------------------------------------------------------------
# Q1(c) AFFINE CIPHER: C = (aP + b) mod 26
# ---------------------------------------------------------------------------
def affine_encrypt(plaintext, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26")
    answer = ""
    for ch in clean_text(plaintext):
        value = a * (ord(ch) - ord("A")) + b
        answer += chr(value % 26 + ord("A"))
    return answer


def affine_decrypt(ciphertext, a, b):
    inverse_a = mod_inverse(a)
    answer = ""
    for ch in clean_text(ciphertext):
        value = inverse_a * ((ord(ch) - ord("A")) - b)
        answer += chr(value % 26 + ord("A"))
    return answer


def affine_key_from_known_pair(p1, p2, c1, c2):
    """Find (a,b) when two plaintext/ciphertext letters are known."""
    p1, p2, c1, c2 = [ord(x.upper()) - 65 for x in (p1, p2, c1, c2)]
    a = ((c2 - c1) * mod_inverse((p2 - p1) % 26)) % 26
    b = (c1 - a * p1) % 26
    return a, b


# ---------------------------------------------------------------------------
# Q2(a) VIGENERE CIPHER
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Q2(b) AUTOKEY CIPHER (numeric starting key)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Q3 PLAYFAIR CIPHER
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Q4 HILL CIPHER (2 x 2 key)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# KEYED BLOCK TRANSPOSITION (also gives a decrypt function for reference)
# key=[2, 0, 1] means output positions 2, 0, 1 from every block.
# ---------------------------------------------------------------------------
def transposition_encrypt(plaintext, key):
    text = clean_text(plaintext)
    while len(text) % len(key) != 0:
        text += "X"
    answer = ""
    for i in range(0, len(text), len(key)):
        block = text[i:i + len(key)]
        answer += "".join(block[position] for position in key)
    return answer


def transposition_decrypt(ciphertext, key):
    text = clean_text(ciphertext)
    answer = ""
    for i in range(0, len(text), len(key)):
        encrypted_block = text[i:i + len(key)]
        plain_block = [""] * len(key)
        for encrypted_position, plain_position in enumerate(key):
            plain_block[plain_position] = encrypted_block[encrypted_position]
        answer += "".join(plain_block)
    return answer


def known_plaintext_transposition_attack(plaintext, ciphertext):
    """Try possible block sizes and print matching permutation keys."""
    plaintext, ciphertext = clean_text(plaintext), clean_text(ciphertext)
    for size in range(2, min(9, len(plaintext) + 1)):
        if len(plaintext) == len(ciphertext) and len(plaintext) % size == 0:
            for key in permutations(range(size)):
                if transposition_encrypt(plaintext, key) == ciphertext:
                    print("Block size:", size, "Permutation key:", list(key))


# ===========================================================================
# STANDARD EXAM INTERFACE - SAME NAMES USED IN EVERY LAB FILE
# Use these two names in a combined/menu-driven exam question.
# Algorithm-specific functions above are kept because they are easier to study.
# ===========================================================================
def encrypt_data(data, key, algorithm="additive", **options):
    """Encrypt data using the selected classical cipher."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm in ("additive", "caesar"):
        return additive_encrypt(data, key)
    if algorithm == "multiplicative":
        return multiplicative_encrypt(data, key)
    if algorithm == "affine":
        a, b = key
        return affine_encrypt(data, a, b)
    if algorithm == "vigenere":
        return vigenere_encrypt(data, key)
    if algorithm == "autokey":
        return autokey_encrypt(data, key)
    if algorithm == "playfair":
        return playfair_encrypt(data, key)
    if algorithm == "hill":
        return hill_encrypt(data, key)
    if algorithm in ("transposition", "keyed-transposition"):
        return transposition_encrypt(data, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def decrypt_data(encrypted_data, key, algorithm="additive", **options):
    """Decrypt data using the selected classical cipher."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm in ("additive", "caesar"):
        return additive_decrypt(encrypted_data, key)
    if algorithm == "multiplicative":
        return multiplicative_decrypt(encrypted_data, key)
    if algorithm == "affine":
        a, b = key
        return affine_decrypt(encrypted_data, a, b)
    if algorithm == "vigenere":
        return vigenere_decrypt(encrypted_data, key)
    if algorithm == "autokey":
        return autokey_decrypt(encrypted_data, key)
    if algorithm == "playfair":
        return playfair_decrypt(encrypted_data, key)
    if algorithm == "hill":
        return hill_decrypt(encrypted_data, key)
    if algorithm in ("transposition", "keyed-transposition"):
        return transposition_decrypt(encrypted_data, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def demo():
    print("\nQ1 - Additive, Multiplicative and Affine")
    message = "I am learning information security"
    tests = [
        ("Additive", additive_encrypt(message, 20), lambda c: additive_decrypt(c, 20)),
        ("Multiplicative", multiplicative_encrypt(message, 15), lambda c: multiplicative_decrypt(c, 15)),
        ("Affine", affine_encrypt(message, 15, 20), lambda c: affine_decrypt(c, 15, 20)),
    ]
    for name, encrypted, decrypt_function in tests:
        print(name, "encrypted:", encrypted)
        print(name, "decrypted:", decrypt_function(encrypted))

    print("\nQ2 - Vigenere and Autokey")
    message = "the house is being sold tonight"
    encrypted = vigenere_encrypt(message, "dollars")
    print("Vigenere:", encrypted, "->", vigenere_decrypt(encrypted, "dollars"))
    encrypted = autokey_encrypt(message, 7)
    print("Autokey:", encrypted, "->", autokey_decrypt(encrypted, 7))

    print("\nQ3 - Playfair")
    encrypted = playfair_encrypt("The key is hidden under the door pad", "GUIDANCE")
    print(encrypted, "->", playfair_decrypt(encrypted, "GUIDANCE"))

    print("\nQ4 - Hill")
    key = [[3, 3], [2, 7]]
    encrypted = hill_encrypt("We live in an insecure world", key)
    print(encrypted, "->", hill_decrypt(encrypted, key))

    print("\nQ5 - Known-plaintext attack")
    print("CIW -> YES means shift key =", (ord("C") - ord("Y")) % 26)
    print("XVIEWYWI decrypts to:", additive_decrypt("XVIEWYWI", 4))

    print("\nQ6 - Affine known pair AB -> GL")
    a, b = affine_key_from_known_pair("A", "B", "G", "L")
    cipher = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    print("Key:", (a, b), "Plaintext:", affine_decrypt(cipher, a, b))


if __name__ == "__main__":
    demo()
