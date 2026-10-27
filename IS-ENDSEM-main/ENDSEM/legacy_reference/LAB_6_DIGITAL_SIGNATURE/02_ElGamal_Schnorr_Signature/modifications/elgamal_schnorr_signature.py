import hashlib
import math
## EL gamal::::::::
# Public key:
# y = g^x mod p
#
# Signature:
# r = g^k mod p
# s = k⁻¹(h - xr) mod (p-1)
#
# Verification:
# y^r × r^s ≡ g^h mod p

# p → prime
# g → generator
# x → private key
# y → public key
# k → random temporary value
# h → hash
# r,s → signature


##Schnorr::::::::::
# Public key:
# y = g^x mod p
#
# Signature:
# r = g^k mod p
# e = H(message || r) mod q
# s = k + xe mod q
#
# Verification:
# g^s ≡ r × y^e mod p

# p → prime
# q → subgroup order
# g → generator
# x → private key
# y → public key
# k → random temporary value
# r → commitment
# e → challenge
# s → response

def hash_message(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)


# ================= ELGAMAL =================

def elgamal_sign(message):
    p = 467
    g = 2

    private_key = 127
    public_key = pow(g, private_key, p)

    k = 61                         # gcd(k, p-1) = 1
    h = hash_message(message) % (p - 1)

    r = pow(g, k, p)

    k_inverse = pow(k, -1, p - 1)
    s = (k_inverse * (h - private_key * r)) % (p - 1)

    return public_key, (r, s)


def elgamal_verify(message, public_key, signature):
    p = 467

    r, s = signature
    h = hash_message(message) % (p - 1)

    left = (pow(public_key, r, p) * pow(r, s, p)) % p
    right = pow(2, h, p)

    return left == right


# ================= SCHNORR =================

def schnorr_sign(message):
    p = 23
    q = 11
    g = 2

    private_key = 3
    public_key = pow(g, private_key, p)

    k = 5

    r = pow(g, k, p)

    e = hash_message(message + str(r)) % q

    s = (k + private_key * e) % q

    return public_key, (r, s)


def schnorr_verify(message, public_key, signature):
    p = 23
    q = 11
    g = 2

    r, s = signature

    e = hash_message(message + str(r)) % q

    left = pow(g, s, p)
    right = (r * pow(public_key, e, p)) % p

    return left == right


# ================= MAIN =================

message = "Alice"

# ElGamal
elg_public, elg_signature = elgamal_sign(message)

print("ELGAMAL")
print("Public Key:", elg_public)
print("Signature:", elg_signature)
print("Verified:", elgamal_verify(message, elg_public, elg_signature))


# Schnorr
sch_public, sch_signature = schnorr_sign(message)

print("\nSCHNORR")
print("Public Key:", sch_public)
print("Signature:", sch_signature)
print("Verified:", schnorr_verify(message, sch_public, sch_signature))