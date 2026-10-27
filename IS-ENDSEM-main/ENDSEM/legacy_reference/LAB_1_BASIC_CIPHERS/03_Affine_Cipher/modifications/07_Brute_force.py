from math import gcd


def inverse(k):
    for i in range(26):
        if (k * i) % 26 == 1:
            return i
    return -1


def decrypt(text, k1, k2):
    result = ""
    k1_inverse = inverse(k1)

    for ch in text:
        if ch.isalpha():
            c = ord(ch) - ord('a')
            p = ((c - k2) * k1_inverse) % 26
            result += chr(p + ord('a'))
        else:
            result += ch

    return result


ciphertext = input("Enter ciphertext: ").lower()

for k1 in range(26):
    if gcd(k1, 26) == 1:
        for k2 in range(26):
            print("k1 =", k1, "k2 =", k2,
                  ":", decrypt(ciphertext, k1, k2))