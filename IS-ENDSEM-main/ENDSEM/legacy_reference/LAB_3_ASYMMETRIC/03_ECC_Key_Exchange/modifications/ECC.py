# BASIC IDEA:
# 1. Sender and receiver generate ECC key pairs.
# 2. They exchange their public keys.
# 3. Using ECDH, both independently derive the same shared secret.
#    The shared secret itself is never transmitted.
# 4. HKDF (HMAC-based Key Derivation Function) derives a
#    symmetric AES key from the shared secret.
# 5. AES-GCM is then used to encrypt and decrypt the message.

#Q: Why can't we just use ECC itself for encryption?
#ECC is a public-key cryptographic framework based on elliptic-curve operations. In practical systems, ECC is mainly used for key establishment or digital signatures rather than directly encrypting bulk data. For encryption, we can use ECDH to establish a shared secret, use HKDF to derive a symmetric key, and then use AES for the actual data encryption. Alternatively, an ECC version of ElGamal can be used, where we generate two ciphertext points C1 and C2
#OR We can use an ECC version of ElGamal. The procedure is analogous to ordinary ElGamal, except the values are elliptic-curve points. Encryption produces C1 and C2, and the private key is used to recover the message point.

#AES is symmetric, so both parties need to already possess the same secret key. The problem is securely establishing that key. ECC with ECDH allows the two parties to establish a shared secret over an insecure channel without transmitting the secret itself. HKDF derives an AES key from that shared secret, and AES is then used for efficient encryption of the actual data




import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


#generate key pair using ecc
def generate_keys():
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    return private_key, public_key

#generate shared secret using ECDH
def generate_shared_secret(private_key, public_key):
    shared_secret = private_key.exchange(
        ec.ECDH(),
        public_key
    )

    return shared_secret

#derive aes key using HKDF
#basically ecc generated key pair-> shared secret-> aes key generation using hkdf, that uses the shared secret generated

def derive_aes_key(shared_secret):

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC Secure Transaction"
    ).derive(shared_secret)
    return aes_key

#encrypt using AES-GCM:
def encrypt_message(message, aes_key):

    aes = AESGCM(aes_key)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(nonce,message.encode(),None)

    return nonce, ciphertext

#decrypt using AES-GCM:
def decrypt_message(nonce, ciphertext, aes_key):
    aes = AESGCM(aes_key)

    plaintext = aes.decrypt(nonce,ciphertext,None)

    return plaintext.decode()

def main():

    plaintext = "Secure Transactions"

    # ----------------------------------------------

    #key generation:
    #-----------------------
    #sender's ECC keys:
    sender_private, sender_public = generate_keys()
    # -----------------------
    #receiver's ECC keys:
    receiver_private, receiver_public = generate_keys()

    print("ECC curve: secp256r1")

    # ----------------------------------------------

    #ECDH:

    sender_secret = generate_shared_secret(
        sender_private,
        receiver_public
    )

    receiver_secret = generate_shared_secret(
        receiver_private,
        sender_public
    )

    print("\nShared Secret same: ", sender_secret == receiver_secret)

    # ----------------------------------------------

    #HKDF

    sender_aes_key = derive_aes_key(sender_secret)

    receiver_aes_key = derive_aes_key(receiver_secret)

    print("AES key same: ", sender_aes_key == receiver_aes_key)

    # ----------------------------------------------

    #encryption:

    nonce, ciphertext = encrypt_message(
        plaintext,
        sender_aes_key
    )

    print("\nPlaintext:")
    print(plaintext)

    print("\nCiphertext:")
    print(ciphertext.hex())

    #decryption:

    decrypted = decrypt_message(
        nonce,
        ciphertext,
        receiver_aes_key
    )

    print("\nDecrypted:")
    print(decrypted)

    # ----------------------------------------------

    print("\nVerification:",decrypted==plaintext)

if __name__ == "__main__":
    main()