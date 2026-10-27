def inverse(key, n):
    for i in range(n):
        if (key * i) % n == 1:
            return i
    return -1


def encrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""

    for ch in text:
        if ch in alphabet:
            p = alphabet.index(ch)
            c = (p * key) % 62
            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""

    key_inverse = inverse(key, 62)

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            p = (c * key_inverse) % 62
            result += alphabet[p]
        else:
            result += ch

    return result


text = input("Enter text: ")
key = int(input("Enter key: "))

if inverse(key, 62) == -1:
    print("Invalid key!")
    print("Key must be relatively prime to 62.")
else:
    ciphertext = encrypt(text, key)

    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypt(ciphertext, key))