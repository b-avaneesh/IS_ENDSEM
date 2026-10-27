def encrypt(text, key):
    result = ""

    for i in range(len(text)):
        p = ord(text[i]) - ord('a')
        k = ord(key[i % len(key)]) - ord('a')

        c = (p + k) % 26

        result += chr(c + ord('a'))

    return result


def decrypt(text, key):
    result = ""

    for i in range(len(text)):
        c = ord(text[i]) - ord('a')
        k = ord(key[i % len(key)]) - ord('a')

        p = (c - k) % 26

        result += chr(p + ord('a'))

    return result


text = input("Enter text: ").lower()
key = input("Enter key: ").lower()

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))