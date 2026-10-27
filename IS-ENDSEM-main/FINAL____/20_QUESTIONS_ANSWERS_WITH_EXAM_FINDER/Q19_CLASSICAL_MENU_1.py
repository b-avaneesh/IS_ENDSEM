# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - No users, RSA, hashes, timestamps or persistent storage are required.
# - Provide additive, multiplicative and affine encrypt/decrypt choices.
# - Validate that multiplicative key and affine a are coprime with 26.
# - Include additive brute force and affine known-plaintext key recovery.
# =====================================================================
"""Additive, multiplicative and affine menu with attacks."""

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


def main():
    print("1 Additive  2 Multiplicative  3 Affine  4 Additive brute force  5 Known affine pair")
    choice = input("Choice: "); text = input("Text: ")
    if choice == "1":
        key = int(input("Key: ")); encrypted = additive_encrypt(text, key); print(encrypted, additive_decrypt(encrypted, key))
    elif choice == "2":
        key = int(input("Coprime key: ")); encrypted = multiplicative_encrypt(text, key); print(encrypted, multiplicative_decrypt(encrypted, key))
    elif choice == "3":
        a, b = int(input("a: ")), int(input("b: ")); encrypted = affine_encrypt(text, a, b); print(encrypted, affine_decrypt(encrypted, a, b))
    elif choice == "4":
        for key, result in additive_brute_force(text): print(key, result)
    else:
        values = [int(input(label)) for label in ("p1: ", "p2: ", "c1: ", "c2: ")]
        print("Recovered key:", affine_key_from_known_pair(*values))


if __name__ == "__main__": main()
