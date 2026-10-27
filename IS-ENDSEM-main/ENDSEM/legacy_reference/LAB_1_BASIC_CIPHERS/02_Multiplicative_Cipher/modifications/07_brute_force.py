from math import gcd


def inverse(key):
    for i in range(26):
        if (key * i) % 26 == 1:
            return i
    return -1


def decrypt(text, key):
    result = ""
    key_inverse = inverse(key)

    for ch in text:
        if ch.isupper():
            c = ord(ch) - ord('A')
            p = (c * key_inverse) % 26
            result += chr(p + ord('A'))

        elif ch.islower():
            c = ord(ch) - ord('a')
            p = (c * key_inverse) % 26
            result += chr(p + ord('a'))

        else:
            result += ch

    return result


ciphertext = input("Enter ciphertext: ")

for key in range(1, 26):
    if gcd(key, 26) == 1:
        print("Key", key, ":", decrypt(ciphertext, key))