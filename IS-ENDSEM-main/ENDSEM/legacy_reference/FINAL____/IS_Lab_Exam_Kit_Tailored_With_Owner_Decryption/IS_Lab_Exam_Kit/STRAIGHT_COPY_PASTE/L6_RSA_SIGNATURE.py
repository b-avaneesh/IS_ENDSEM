"""RSA digital signature - copy this file. Requires PyCryptodome."""

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def sign_data(data, private_key):
    return pkcs1_15.new(private_key).sign(SHA256.new(data.encode()))


def verify_signature(data, signature, public_key):
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data.encode()), signature)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    data = input("Enter data: ")
    public_key, private_key = generate_keys()
    signature = sign_data(data, private_key)
    print("Signature hex:", signature.hex())
    print("Verified:", verify_signature(data, signature, public_key))

