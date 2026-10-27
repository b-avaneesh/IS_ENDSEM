from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()


# Message
message = input("Enter message: ").encode()


# =====================================================
# CONFIDENTIALITY - RSA ENCRYPTION
# =====================================================

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nEncrypted message:", ciphertext.hex())


# Decryption
decrypted = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Decrypted message:", decrypted.decode())


# =====================================================
# INTEGRITY - SHA-256 HASH
# =====================================================

digest = hashes.Hash(hashes.SHA256())
digest.update(message)
original_hash = digest.finalize()

print("\nSHA-256 Hash:", original_hash.hex())


# =====================================================
# AUTHENTICATION - RSA DIGITAL SIGNATURE
# =====================================================

signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("\nDigital Signature:", signature.hex())


# Verify signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Signature verification: SUCCESS")
    print("Message is authentic and has not been modified.")

except:
    print("Signature verification: FAILED")