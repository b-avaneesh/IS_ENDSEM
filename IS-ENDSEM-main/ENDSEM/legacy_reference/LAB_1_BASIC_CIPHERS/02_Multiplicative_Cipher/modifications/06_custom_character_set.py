def inverse(key, n):
    for i in range(n):
        if (key * i) % n == 1:
            return i
    return -1


def encrypt(text, key, alphabet):
    result = ""
    n = len(alphabet)

    for ch in text:
        if ch in alphabet:
            p = alphabet.index(ch)
            c = (p * key) % n
            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, key, alphabet):
    result = ""
    n = len(alphabet)

    key_inverse = inverse(key, n)

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            p = (c * key_inverse) % n
            result += alphabet[p]
        else:
            result += ch

    return result


alphabet = input("Enter character set: ")
text = input("Enter text: ")
key = int(input("Enter key: "))

if inverse(key, len(alphabet)) == -1:
    print("Invalid key!")
else:
    ciphertext = encrypt(text, key, alphabet)

    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypt(ciphertext, key, alphabet))