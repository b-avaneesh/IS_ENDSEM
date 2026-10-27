
from math import gcd

# Step 1: Key Generation
p = 11
q = 13

n = p * q
phi = (p - 1) * (q - 1)

e = 7

while gcd(e, phi) != 1:
    e += 1

d = pow(e, -1, phi)

print("Public key:", (e, n))
print("Private key:", (d, n))

# Step 2: Encryption
def encrypt(m):
    return pow(m, e, n)

# Step 3: Decryption
def decrypt(c):
    return pow(c, d, n)

# Step 4: Encrypt two integers
m1 = 7
m2 = 3

c1 = encrypt(m1)
c2 = encrypt(m2)

print("Ciphertext of 7:", c1)
print("Ciphertext of 3:", c2)

# Step 5: Homomorphic Multiplication
c_mul = (c1 * c2) % n

print("Encrypted product:", c_mul)

# Step 6: Decrypt the product
result = decrypt(c_mul)

print("Decrypted product:", result)
print("Actual product:", m1 * m2)

if result == (m1 * m2) % n:
    print("Multiplication verified successfully!")
