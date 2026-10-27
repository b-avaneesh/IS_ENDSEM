def encrypt(text, key, alphabet):
    result = ""
    n = len(alphabet)

    for i in range(len(text)):
        ch = text[i]

        if ch in alphabet:
            p = alphabet.index(ch)
            k = alphabet.index(key[i % len(key)])

            c = (p + k) % n

            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, key, alphabet):
    result = ""
    n = len(alphabet)

    for i in range(len(text)):
        ch = text[i]

        if ch in alphabet:
            c = alphabet.index(ch)
            k = alphabet.index(key[i % len(key)])

            p = (c - k) % n

            result += alphabet[p]
        else:
            result += ch

    return result


alphabet = input("Enter alphabet: ")
text = input("Enter text: ")
key = input("Enter key: ")

ciphertext = encrypt(text, key, alphabet)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key, alphabet))