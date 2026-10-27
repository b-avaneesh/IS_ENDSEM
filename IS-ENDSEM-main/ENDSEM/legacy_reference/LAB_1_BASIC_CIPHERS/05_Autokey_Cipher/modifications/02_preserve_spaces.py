def encrypt(text, key):
    result = ""
    key_stream = key
    key_index = 0

    for ch in text:
        if ch == ' ':
            result += ' '
        else:
            p = ord(ch) - ord('a')
            k = ord(key_stream[key_index]) - ord('a')

            c = (p + k) % 26

            encrypted_char = chr(c + ord('a'))

            result += encrypted_char

            key_stream += ch
            key_index += 1

    return result


def decrypt(text, key):
    result = ""
    key_stream = key
    key_index = 0

    for ch in text:
        if ch == ' ':
            result += ' '
        else:
            c = ord(ch) - ord('a')
            k = ord(key_stream[key_index]) - ord('a')

            p = (c - k) % 26

            decrypted_char = chr(p + ord('a'))

            result += decrypted_char

            key_stream += decrypted_char
            key_index += 1

    return result


text = input("Enter text: ").lower()
key = input("Enter key: ").lower()

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))