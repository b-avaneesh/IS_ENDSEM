p = 23
g = 5

# Alice
a = 6
A = pow(g, a, p)

# Bob
b = 15
B = pow(g, b, p)

# Shared secret
alice_secret = pow(B, a, p)
bob_secret = pow(A, b, p)

print("Alice Public:", A)
print("Bob Public:", B)

print("Alice Shared Secret:", alice_secret)
print("Bob Shared Secret:", bob_secret)

print("Keys Match:", alice_secret == bob_secret)