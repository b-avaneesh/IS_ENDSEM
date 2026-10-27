def encrypt(text, key):
    result = ""

    for ch in text:
        if ch == ' ':
            result += ' '
        else:
            p = ord(ch) - ord('a')
            c = (p + key) % 26
            result += chr(c + ord('a'))

    return result


def decrypt(text, key):
    result = ""

    for ch in text:
        if ch == ' ':
            result += ' '
        else:
            c = ord(ch) - ord('a')
            p = (c - key) % 26
            result += chr(p + ord('a'))

    return result


text = input("Enter text: ").lower()
key = int(input("Enter key: "))

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))