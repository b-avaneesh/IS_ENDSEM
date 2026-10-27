def encrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    result = ""
    key_stream = key
    key_index = 0

    for ch in text:
        if ch in alphabet:
            p = alphabet.index(ch)
            k = ord(key_stream[key_index].lower()) - ord('a')

            c = (p + k) % 62

            result += alphabet[c]

            key_stream += ch
            key_index += 1

        else:
            result += ch

    return result


def decrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    result = ""
    key_stream = key
    key_index = 0

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            k = ord(key_stream[key_index].lower()) - ord('a')

            p = (c - k) % 62

            decrypted_char = alphabet[p]

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