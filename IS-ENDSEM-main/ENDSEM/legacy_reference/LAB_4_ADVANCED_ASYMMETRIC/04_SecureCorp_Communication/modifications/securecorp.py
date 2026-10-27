import secrets


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



#===============================================
#DIFFIE-HELLMAN PARAMETERS
#===============================================

p = 467
g = 2

#===============================================
#SYSTEM
#===============================================

class System:

    def __init__(self,name):
        self.name = name
        self.active = True

        #----------------
        #RSA Key pair
        # ----------------

        self.rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        self.rsa_public = self.rsa_private.public_key()

        # ----------------
        #DH key pair
        # ----------------

        self.dh_private = secrets.randbelow(p-2) + 1

        self.dh_public = pow(
            g,
            self.dh_private,
            p
        )

    # ===============================================
    #KEY MANAGEMENT
    # ===============================================

class KeyManager:

    def __init__(self):
        self.systems = {}

    def add_system(self, system):
        self.systems[system.name] = system
        print(system.name, "added.")

    def get_public_keys(self, name):
        system = self.systems[name]

        if not system.active:
            print("System is revoked.")
            return None

        return system.rsa_public, system.dh_public

    def revoke(self, name):
        self.systems[name].active = False
        print(name, "has been revoked.")

# =========================================================
# DH SHARED SECRET
# =========================================================

def create_shared_secret(sender, receiver):

    #sender calculates the shared secret
    sender_secret = pow(
        receiver.dh_public,
        sender.dh_private,
        p
    )

    #receiver calculates the shared secret
    receiver_secret = pow(
        sender.dh_public,
        receiver.dh_private,
        p
    )

    return sender_secret, receiver_secret

# =========================================================
# CONVERT DH SECRET INTO AES KEY
# =========================================================

def make_aes_key(shared_secret):

    digest = hashes.Hash(hashes.SHA256())

    digest.update(
        shared_secret.to_bytes(
            (shared_secret.bit_length() + 7) // 8,
            "big"
        )
    )

    return digest.finalize()


# =========================================================
# RSA DIGITAL SIGNATURE
# =========================================================

def sign_document(system, document):
    signature = system.rsa_private.sign(
        document.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(system, document, signature):

    try:
        system.rsa_public.verify(
            signature,
            document.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH

            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# =========================================================
# ENCRYPT DOCUMENT
# =========================================================

def encrypt_document(document, aes_key):
    aes = AESGCM(aes_key)

    nonce = secrets.token_bytes(12)

    ciphertext = aes.encrypt(
        nonce,
        document.encode(),
        None
    )
    return nonce, ciphertext

# =========================================================
# DECRYPT DOCUMENT
# =========================================================

def decrypt_document(nonce, ciphertext, aes_key):

    aes = AESGCM(aes_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()

# =========================================================
# SECURE COMMUNICATION
# =========================================================

def send_document(sender, receiver, document):
    print("\n" + "=" * 50)
    print(sender.name, "->", receiver.name)
    print("=" * 50)

    if not sender.active or not receiver.active:
        print("Communication failed: system is revoked.")

        return

    # -----------------------------------------------------
    # 1. DIFFIE-HELLMAN
    # -----------------------------------------------------

    sender_secret, receiver_secret = create_shared_secret(
        sender,
        receiver
    )

    print(
        "shared secret same:",
        sender_secret==receiver_secret
    )

    # -----------------------------------------------------
    # 2. CREATE AES KEY
    # -----------------------------------------------------

    sender_aes_key = make_aes_key(sender_secret)
    receiver_aes_key = make_aes_key(receiver_secret)

    # -----------------------------------------------------
    # 3. RSA DIGITAL SIGNATURE
    # -----------------------------------------------------

    signature = sign_document(
        sender,
        document
    )

    print(
        "RSA signature valid:",
        verify_signature(
            sender,
            document,
            signature
        )
    )

    # -----------------------------------------------------
    # 4. ENCRYPT DOCUMENT USING AES
    # -----------------------------------------------------

    nonce, ciphertext = encrypt_document(
        document,
        sender_aes_key
    )

    print(
        "Encrypted document:",
        ciphertext.hex()
    )
    # -----------------------------------------------------
    # 5. RECEIVER DECRYPTS
    # -----------------------------------------------------

    decrypted = decrypt_document(
        nonce,
        ciphertext,
        receiver_aes_key
    )

    print(
        "Decrypted document: ",
        decrypted
    )

    print(
        "Verification:",
        decrypted == document
    )

def main():

    print("=" * 50)
    print("SECURE SECURE COMMUNICATION SYSTEM")
    print("=" *50)

    # -----------------------------------------------------
    # KEY MANAGEMENT SERVICE
    # ----------------------------------------------------

    key_manager = KeyManager()

    #-----------------------------------------------------
    # CREATE SYSTEMS
    # -----------------------------------------------------

    finance = System("Finance System")
    hr = System("HR System")
    supply = System("Supply Chain System")

    # -----------------------------------------------------
    #REGISTER SYSTEMS
    # -----------------------------------------------------

    key_manager.add_system(finance)
    key_manager.add_system(hr)
    key_manager.add_system(supply)

    # -----------------------------------------------------
    #key distribution
    # -----------------------------------------------------

    print("\nPublic keys of HR:")
    rsa_public, dh_public = key_manager.get_public_keys("HR System")

    print("RSA public key received.",rsa_public)
    print("DH public key:",dh_public)

    # -----------------------------------------------------
    #SECURE DOCUMENT TRANSFER
    # -----------------------------------------------------

    send_document(
        finance,
        hr,
        "Confidential Financial Report"
    )

    send_document(
        hr,
        supply,
        "Employee Contract"
    )

    # -----------------------------------------------------
    # KEY REVOCATION
    # -----------------------------------------------------

    print("\nRevoking HR System...")

    key_manager.revoke(
        "HR System"
    )

    # -----------------------------------------------------
    # TRY COMMUNICATION AFTER REVOCATION
    # -----------------------------------------------------

    send_document(
        finance,
        hr,
        "Financial Report"
    )

    # -----------------------------------------------------
    # SCALABILITY
    # -----------------------------------------------------

    print("\nAdding new subsystem...")

    marketing = System(
        "Marketing System"
    )

    key_manager.add_system(
        marketing
    )

main()