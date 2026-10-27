def inverse(k, n):
    for i in range(n):
        if (k * i) % n == 1:
            return i
    return -1


def encrypt(text, k1, k2):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    n = len(alphabet)

    result = ""

    for ch in text:
        if ch in alphabet:
            p = alphabet.index(ch)
            c = (p * k1 + k2) % n
            result += alphabet[c]
        else:
            result += ch

    return result


def decrypt(text, k1, k2):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    n = len(alphabet)

    result = ""
    k1_inverse = inverse(k1, n)

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            p = ((c - k2) * k1_inverse) % n
            result += alphabet[p]
        else:
            result += ch

    return result


text = input("Enter text: ")
k1 = int(input("Enter k1: "))
k2 = int(input("Enter k2: "))

if inverse(k1, 62) == -1:
    print("Invalid k1!")
else:
    ciphertext = encrypt(text, k1, k2)

    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypt(ciphertext, k1, k2))