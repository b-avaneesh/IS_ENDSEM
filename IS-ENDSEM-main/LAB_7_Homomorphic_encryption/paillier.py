
import random
from math import gcd

# Step 1: Key Generation
p = 17
q = 19

n = p * q
n2 = n * n
g = n + 1

lam = (p - 1) * (q - 1)

mu = pow(lam, -1, n)

# Step 2: Encryption
def encrypt(m):
    r = random.randint(1, n - 1)

    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c

# Step 3: Decryption
def decrypt(c):
    u = pow(c, lam, n2)
    L = (u - 1) // n
    m = (L * mu) % n
    return m

# Step 4: Encrypt two integers
m1 = 15
m2 = 25

c1 = encrypt(m1)
c2 = encrypt(m2)

print("Ciphertext of 15:", c1)
print("Ciphertext of 25:", c2)

# Step 5: Homomorphic Addition
c_add = (c1 * c2) % n2

print("Encrypted sum:", c_add)

# Step 6: Decrypt the sum
result = decrypt(c_add)

print("Decrypted sum:", result)
print("Actual sum:", m1 + m2)

if result == m1 + m2:
    print("Addition verified successfully!")
