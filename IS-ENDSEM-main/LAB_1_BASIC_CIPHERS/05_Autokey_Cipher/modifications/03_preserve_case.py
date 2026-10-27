def encrypt(text, key):
    result = ""
    key_stream = key
    key_index = 0

    for ch in text:
        if ch.isupper():
            p = ord(ch) - ord('A')
            k = ord(key_stream[key_index].lower()) - ord('a')

            c = (p + k) % 26

            result += chr(c + ord('A'))

            key_stream += ch.lower()
            key_index += 1

        elif ch.islower():
            p = ord(ch) - ord('a')
            k = ord(key_stream[key_index].lower()) - ord('a')

            c = (p + k) % 26

            result += chr(c + ord('a'))

            key_stream += ch
            key_index += 1

        else:
            result += ch

    return result


def decrypt(text, key):
    result = ""
    key_stream = key
    key_index = 0

    for ch in text:
        if ch.isupper():
            c = ord(ch) - ord('A')
            k = ord(key_stream[key_index].lower()) - ord('a')

            p = (c - k) % 26

            decrypted_char = chr(p + ord('A'))

            result += decrypted_char

            key_stream += decrypted_char.lower()
            key_index += 1

        elif ch.islower():
            c = ord(ch) - ord('a')
            k = ord(key_stream[key_index].lower()) - ord('a')

            p = (c - k) % 26

            decrypted_char = chr(p + ord('a'))

            result += decrypted_char

            key_stream += decrypted_char
            key_index += 1

        else:
            result += ch

    return result


text = input("Enter text: ")
key = input("Enter key: ").lower()

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))