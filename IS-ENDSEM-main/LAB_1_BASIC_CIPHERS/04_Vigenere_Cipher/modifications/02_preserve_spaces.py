def encrypt(text, key):
    result = ""
    key_index = 0

    for ch in text:
        if ch == ' ':
            result += ' '
        else:
            p = ord(ch) - ord('a')
            k = ord(key[key_index % len(key)]) - ord('a')

            c = (p + k) % 26

            result += chr(c + ord('a'))
            key_index += 1

    return result


def decrypt(text, key):
    result = ""
    key_index = 0

    for ch in text:
        if ch == ' ':
            result += ' '
        else:
            c = ord(ch) - ord('a')
            k = ord(key[key_index % len(key)]) - ord('a')

            p = (c - k) % 26

            result += chr(p + ord('a'))
            key_index += 1

    return result


text = input("Enter text: ").lower()
key = input("Enter key: ").lower()

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))