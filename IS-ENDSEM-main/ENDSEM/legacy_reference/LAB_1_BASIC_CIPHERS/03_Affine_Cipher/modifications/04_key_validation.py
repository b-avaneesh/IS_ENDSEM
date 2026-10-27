from math import gcd


def inverse(k):
    for i in range(26):
        if (k * i) % 26 == 1:
            return i
    return -1


def encrypt(text, k1, k2):
    result = ""

    for ch in text:
        p = ord(ch) - ord('a')
        c = (p * k1 + k2) % 26
        result += chr(c + ord('a'))

    return result


def decrypt(text, k1, k2):
    result = ""
    k1_inverse = inverse(k1)

    for ch in text:
        c = ord(ch) - ord('a')
        p = ((c - k2) * k1_inverse) % 26
        result += chr(p + ord('a'))

    return result


text = input("Enter text: ")
k1 = int(input("Enter k1: "))
k2 = int(input("Enter k2: "))

if gcd(k1, 26) != 1:
    print("Invalid k1!")
    print("k1 must be relatively prime to 26.")
else:
    ciphertext = encrypt(text, k1, k2)

    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypt(ciphertext, k1, k2))