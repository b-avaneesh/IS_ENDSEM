"""Lab 7: multiply encrypted integers with textbook RSA or ElGamal.

This is a menu-driven, standalone exercise. It does not save records.
Textbook RSA is used only to demonstrate multiplicative homomorphism;
RSA-OAEP does not provide the same multiplication rule.
"""

import secrets

# QUICK EDIT: change the two input values in the menu, or call rsa_product(a, b)
# or elgamal_product(a, b) directly. Both results are modulo their public
# modulus, so use small examples such as 7 and 3 for an ordinary product.


def rsa_product(a, b):
    # Small classroom key: n=17*19, e=5, d=173. Replace the whole key together.
    n, e, d = 323, 5, 173
    if not (0 <= a < n and 0 <= b < n):
        raise ValueError('RSA inputs must each be between 0 and 322.')
    c1, c2 = pow(a, e, n), pow(b, e, n)
    combined = c1 * c2 % n      # E(a) * E(b) = E(a*b) mod n.
    result = pow(combined, d, n)
    assert result == (a * b) % n
    return c1, c2, combined, result, n


def elgamal_product(a, b):
    # Small classroom group; random k gives fresh ciphertexts each run.
    p, g, private = 467, 2, 127
    public = pow(g, private, p)
    if not (1 <= a < p and 1 <= b < p):
        raise ValueError('ElGamal inputs must each be between 1 and 466.')

    def encrypt(m):
        k = secrets.randbelow(p - 2) + 1
        return (pow(g, k, p), m * pow(public, k, p) % p)

    c1, c2 = encrypt(a), encrypt(b)
    combined = (c1[0] * c2[0] % p, c1[1] * c2[1] % p)
    shared = pow(combined[0], private, p)
    result = combined[1] * pow(shared, -1, p) % p
    assert result == (a * b) % p
    return c1, c2, combined, result, p


def main():
    while True:
        print('\n1 RSA encrypted product\n2 ElGamal encrypted product\n3 Exit')
        try:
            choice = input('Input Choice: ').strip()
            if choice == '3':
                return
            if choice not in ('1', '2'):
                print('Invalid choice.')
                continue
            a = int(input('First integer: '))
            b = int(input('Second integer: '))
            first, second, combined, result, modulus = (
                rsa_product(a, b) if choice == '1' else elgamal_product(a, b)
            )
            print('First ciphertext:', first)
            print('Second ciphertext:', second)
            print('Combined ciphertext:', combined)
            print('Decrypted product:', result)
            print('Expected (a*b) mod', modulus, ':', (a * b) % modulus)
        except ValueError as error:
            print('Rejected:', error)
        except (EOFError, KeyboardInterrupt):
            return


if __name__ == '__main__':
    main()
