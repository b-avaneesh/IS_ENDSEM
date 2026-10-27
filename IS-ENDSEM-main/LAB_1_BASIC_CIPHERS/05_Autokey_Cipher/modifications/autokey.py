def encrypt(text, key):
    result = ""

    key_stream = key

    for i in range(len(text)):
        p = ord(text[i]) - ord('a')
        k = ord(key_stream[i]) - ord('a')

        c = (p + k) % 26

        result += chr(c + ord('a'))

        key_stream += text[i]

    return result


def decrypt(text, key):
    result = ""

    key_stream = key

    for i in range(len(text)):
        c = ord(text[i]) - ord('a')
        k = ord(key_stream[i]) - ord('a')

        p = (c - k) % 26

        result += chr(p + ord('a'))

        key_stream += result[i]

    return result


text = input("Enter text: ").lower()
key = input("Enter key: ").lower()

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))