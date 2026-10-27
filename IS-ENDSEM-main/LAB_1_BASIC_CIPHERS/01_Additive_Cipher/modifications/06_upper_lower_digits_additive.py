def encrypt(text, key):
    result = ""

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    for ch in text:
        if ch in alphabet:
            p = alphabet.index(ch)
            c = (p + key) % 62
            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, key):
    result = ""

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            p = (c - key) % 62
            result += alphabet[p]
        else:
            result += ch

    return result


text = input("Enter text: ")
key = int(input("Enter key: "))

ciphertext = encrypt(text, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypt(ciphertext, key))