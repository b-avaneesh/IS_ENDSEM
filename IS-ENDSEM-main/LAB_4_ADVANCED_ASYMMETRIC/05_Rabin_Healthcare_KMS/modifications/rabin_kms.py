import secrets
import time
import logging
from datetime import datetime, timedelta


# =========================================================
# AUDITING / LOGGING
# =========================================================

logging.basicConfig(
    filename="key_management.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# =========================================================
# RABIN KEY GENERATION
# =========================================================

def generate_prime(bits):

    # Generate a prime of the required size
    while True:

        # Generate a random odd number
        candidate = secrets.randbits(bits)

        candidate |= (1 << bits - 1)
        candidate |= 1

        # Rabin requires p and q to be 3 mod 4
        if candidate % 4 != 3:
            continue

        if is_prime(candidate):
            return candidate


def is_prime(n):

    if n < 2:
        return False

    if n % 2 == 0:
        return n == 2

    i = 3

    while i * i <= n:

        if n % i == 0:
            return False

        i += 2

    return True


def generate_rabin_keys(key_size=1024):

    start = time.perf_counter()

    # Generate two primes
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)

    # Make sure p and q are different
    while q == p:
        q = generate_prime(key_size // 2)

    # Public key
    n = p * q

    # Private key
    private_key = (p, q)

    end = time.perf_counter()

    return n, private_key, end - start


# =========================================================
# RABIN ENCRYPTION
# =========================================================

def rabin_encrypt(message, public_key):

    n = public_key

    ciphertext = []

    for ch in message:

        # Convert character to integer
        m = ord(ch)

        # Rabin encryption:
        # c = m^2 mod n
        c = pow(m, 2, n)

        ciphertext.append(c)

    return ciphertext


# =========================================================
# RABIN DECRYPTION
# =========================================================

def rabin_decrypt(ciphertext, private_key, public_key):

    p, q = private_key
    n = public_key

    plaintext = ""

    for c in ciphertext:

        # Calculate square roots modulo p and q

        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)

        # Extended Euclidean algorithm
        yp, yq, gcd_value = extended_gcd(p, q)

        # CRT combinations

        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1

        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3

        # Rabin produces four possible roots.
        roots = [r1, r2, r3, r4]

        # Find the root corresponding to an ASCII character
        found = False

        for root in roots:

            if 0 <= root <= 127:

                plaintext += chr(root)
                found = True
                break

        if not found:
            plaintext += "?"

    return plaintext


# =========================================================
# EXTENDED EUCLIDEAN ALGORITHM
# =========================================================

def extended_gcd(a, b):

    if b == 0:
        return 1, 0, a

    x1, y1, gcd_value = extended_gcd(
        b,
        a % b
    )

    x = y1
    y = x1 - (a // b) * y1

    return x, y, gcd_value


# =========================================================
# KEY MANAGEMENT SERVICE
# =========================================================

class KeyManagementService:

    def __init__(self, key_size=1024):

        self.key_size = key_size

        # Stores information about all facilities
        self.facilities = {}


    # -----------------------------------------------------
    # Register facility
    # -----------------------------------------------------

    def register_facility(self, name):

        if name in self.facilities:

            print(name, "is already registered.")
            return

        print("\nGenerating keys for", name)

        public_key, private_key, generation_time = \
            generate_rabin_keys(self.key_size)

        self.facilities[name] = {

            "public_key": public_key,

            "private_key": private_key,

            "created": datetime.now(),

            "expiry": datetime.now() + timedelta(days=365),

            "status": "active"
        }

        logging.info(
            "KEY_GENERATED facility=%s",
            name
        )

        print(
            "Key generation time:",
            generation_time,
            "seconds"
        )

        print(name, "registered successfully.")


    # -----------------------------------------------------
    # Key distribution
    # -----------------------------------------------------

    def get_keys(self, name):

        if name not in self.facilities:

            print("Facility not found.")
            return None

        facility = self.facilities[name]

        if facility["status"] == "revoked":

            print("Access denied. Facility key is revoked.")

            logging.warning(
                "KEY_REQUEST_DENIED facility=%s",
                name
            )

            return None

        logging.info(
            "KEY_DISTRIBUTED facility=%s",
            name
        )

        return (
            facility["public_key"],
            facility["private_key"]
        )


    # -----------------------------------------------------
    # Key revocation
    # -----------------------------------------------------

    def revoke_key(self, name):

        if name not in self.facilities:

            print("Facility not found.")
            return

        self.facilities[name]["status"] = "revoked"

        logging.warning(
            "KEY_REVOKED facility=%s",
            name
        )

        print(
            name,
            "key has been revoked."
        )


    # -----------------------------------------------------
    # Key renewal
    # -----------------------------------------------------

    def renew_key(self, name):

        if name not in self.facilities:

            print("Facility not found.")
            return

        print("\nRenewing key for", name)

        public_key, private_key, generation_time = \
            generate_rabin_keys(self.key_size)

        self.facilities[name]["public_key"] = public_key
        self.facilities[name]["private_key"] = private_key

        self.facilities[name]["created"] = datetime.now()

        self.facilities[name]["expiry"] = \
            datetime.now() + timedelta(days=365)

        self.facilities[name]["status"] = "active"

        logging.info(
            "KEY_RENEWED facility=%s",
            name
        )

        print(
            "New key generated in:",
            generation_time,
            "seconds"
        )


    # -----------------------------------------------------
    # Automatically renew expired keys
    # -----------------------------------------------------

    def renew_expired_keys(self):

        current_time = datetime.now()

        for name, facility in self.facilities.items():

            if facility["expiry"] <= current_time:

                self.renew_key(name)


    # -----------------------------------------------------
    # Display facilities
    # -----------------------------------------------------

    def display_facilities(self):

        print("\n" + "=" * 60)
        print("REGISTERED FACILITIES")
        print("=" * 60)

        for name, facility in self.facilities.items():

            print("\nFacility:", name)
            print("Public key:", facility["public_key"])
            print("Status:", facility["status"])
            print("Created:", facility["created"])
            print("Expiry:", facility["expiry"])


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 60)
    print("HEALTHCARE INC. KEY MANAGEMENT SERVICE")
    print("=" * 60)

    # -----------------------------------------------------
    # Create centralized KMS
    # -----------------------------------------------------

    kms = KeyManagementService(
        key_size=1024
    )


    # -----------------------------------------------------
    # Register hospitals and clinics
    # -----------------------------------------------------

    kms.register_facility(
        "Hospital A"
    )

    kms.register_facility(
        "Hospital B"
    )

    kms.register_facility(
        "Clinic C"
    )


    # -----------------------------------------------------
    # Display registered facilities
    # -----------------------------------------------------

    kms.display_facilities()


    # -----------------------------------------------------
    # Key distribution
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("KEY DISTRIBUTION")
    print("=" * 60)

    keys = kms.get_keys(
        "Hospital A"
    )

    if keys:

        public_key, private_key = keys

        print(
            "\nHospital A public key:",
            public_key
        )

        print(
            "Hospital A private key:",
            private_key
        )


    # -----------------------------------------------------
    # Demonstrate Rabin encryption/decryption
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("RABIN ENCRYPTION / DECRYPTION")
    print("=" * 60)

    message = "HELLO"

    ciphertext = rabin_encrypt(
        message,
        public_key
    )

    print("\nOriginal message:")
    print(message)

    print("\nCiphertext:")
    print(ciphertext)

    decrypted = rabin_decrypt(
        ciphertext,
        private_key,
        public_key
    )

    print("\nDecrypted message:")
    print(decrypted)

    print(
        "\nVerification:",
        decrypted == message
    )


    # -----------------------------------------------------
    # Key revocation
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("KEY REVOCATION")
    print("=" * 60)

    kms.revoke_key(
        "Hospital B"
    )


    # -----------------------------------------------------
    # Try requesting revoked key
    # -----------------------------------------------------

    kms.get_keys(
        "Hospital B"
    )


    # -----------------------------------------------------
    # Key renewal
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("KEY RENEWAL")
    print("=" * 60)

    kms.renew_key(
        "Hospital B"
    )


    # -----------------------------------------------------
    # Automatic renewal
    # -----------------------------------------------------

    kms.renew_expired_keys()


    # -----------------------------------------------------
    # Final status
    # -----------------------------------------------------

    kms.display_facilities()


if __name__ == "__main__":
    main()