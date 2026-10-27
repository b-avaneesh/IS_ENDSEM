"""Lab 7: multiply one Paillier-encrypted integer by a public scalar.

This is a menu-driven, standalone exercise. It does not save records.
It computes k*m mod n; it does not multiply two encrypted unknown values.
"""

import math
import secrets

# QUICK EDIT: use m=15 and k=3 to see 45. For a different demonstration,
# change the menu inputs. Keep k nonnegative, and keep k*m below n if you
# want the decrypted result to equal the usual integer product without wrap.
P, Q = 53, 59
N = P * Q
G = N + 1
LAMBDA = math.lcm(P - 1, Q - 1)
MU = pow(LAMBDA, -1, N)


def encrypt(m):
    if not 0 <= m < N:
        raise ValueError('Message must be between 0 and n-1.')
    while True:
        r = secrets.randbelow(N - 1) + 1
        if math.gcd(r, N) == 1:
            return (pow(G, m, N * N) * pow(r, N, N * N)) % (N * N)


def decrypt(ciphertext):
    return ((pow(ciphertext, LAMBDA, N * N) - 1) // N) * MU % N


def scalar_multiply(m, k):
    if k < 0:
        raise ValueError('Use a nonnegative scalar.')
    first = encrypt(m)
    combined = pow(first, k, N * N)  # E(m)^k = E(k*m) mod n^2.
    result = decrypt(combined)
    assert result == (m * k) % N
    return first, combined, result


def main():
    while True:
        print('\n1 Paillier encrypted scalar multiplication\n2 Exit')
        try:
            choice = input('Input Choice: ').strip()
            if choice == '2':
                return
            if choice != '1':
                print('Invalid choice.')
                continue
            m = int(input('Integer to encrypt: '))
            k = int(input('Public multiplier: '))
            first, combined, result = scalar_multiply(m, k)
            print('Ciphertext of m:', hex(first))
            print('Ciphertext of k*m:', hex(combined))
            print('Decrypted result:', result)
            print('Expected (k*m) mod n:', (k * m) % N)
        except ValueError as error:
            print('Rejected:', error)
        except (EOFError, KeyboardInterrupt):
            return


if __name__ == '__main__':
    main()
