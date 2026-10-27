from math import gcd


def inverse(key):
    for i in range(26):
        if (key * i) % 26 == 1:
            return i
    return -1


def encrypt(text, key):
    result = ""

    for ch in text:
        if ch.isupper():
            p = ord(ch) - ord('A')
            c = (p * key) % 26
            result += chr(c + ord('A'))

        elif ch.islower():
            p = ord(ch) - ord('a')
            c = (p * key) % 26
            result += chr(c + ord('a'))

        else:
            result += ch

    return result


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


text = input("Enter text: ")
key = int(input("Enter key: "))

if gcd(key, 26) != 1:
    print("Invalid key")
else:
    ciphertext = encrypt(text, key)
    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypt(ciphertext, key))