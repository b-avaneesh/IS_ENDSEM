from math import gcd


def RSA(plaintext):
    p = 10007
    q = 10009

    n = p * q
    phi = (p - 1) * (q - 1)

    # Find e
    e = -1

    for i in range(2, phi):
        if gcd(i, phi) == 1:
            e = i
            break

    # Find d
    d = -1

    for i in range(1, phi):
        if (e * i) % phi == 1:
            d = i
            break

    print("n =", n)
    print("phi =", phi)
    print("e =", e)
    print("d =", d)

    # Encryption
    ciphertext = []

    for ch in plaintext:
        M = ord(ch)
        C = pow(M, e, n)
        ciphertext.append(C)

    print("Ciphertext =", ciphertext)

    # Decryption
    decrypted = ""

    for C in ciphertext:
        M = pow(C, d, n)
        decrypted += chr(M)

    print("Decrypted =", decrypted)


def main():
    plaintext = input("Enter plaintext: ")

    RSA(plaintext)


main()