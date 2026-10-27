def encrypt(text, key, alphabet):
    result = ""
    key_stream = key
    key_index = 0
    n = len(alphabet)

    for ch in text:
        if ch in alphabet:
            p = alphabet.index(ch)
            k = alphabet.index(key_stream[key_index])

            c = (p + k) % n

            result += alphabet[c]

            key_stream += ch
            key_index += 1

        else:
            result += ch

    return result


def decrypt(text, key, alphabet):
    result = ""
    key_stream = key
    key_index = 0
    n = len(alphabet)

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            k = alphabet.index(key_stream[key_index])

            p = (c - k) % n

            decrypted_char = alphabet[p]

            result += decrypted_char

            key_stream += decrypted_char
            key_index += 1

        else:
            result += ch

    return result


alphabet = input("Enter alphabet: ")
text = input("Enter text: ")
key = input("Enter key: ")

ciphertext = encrypt(text, key, alphabet)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key, alphabet))