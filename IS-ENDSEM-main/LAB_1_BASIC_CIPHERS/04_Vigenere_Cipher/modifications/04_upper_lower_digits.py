def encrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""

    for i in range(len(text)):
        ch = text[i]

        if ch in alphabet:
            p = alphabet.index(ch)
            k = ord(key[i % len(key)].lower()) - ord('a')

            c = (p + k) % 62

            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""

    for i in range(len(text)):
        ch = text[i]

        if ch in alphabet:
            c = alphabet.index(ch)
            k = ord(key[i % len(key)].lower()) - ord('a')

            p = (c - k) % 62

            result += alphabet[p]
        else:
            result += ch

    return result


text = input("Enter text: ")
key = input("Enter key: ")

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))