from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generate_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


def sign_message(message, private_key):
    hash_value = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(hash_value)
    return signature


def verify_signature(message, signature, public_key):
    hash_value = SHA256.new(message.encode())

    try:
        pkcs1_15.new(public_key).verify(hash_value, signature)
        return True
    except (ValueError, TypeError):
        return False


# Main
private_key, public_key = generate_keys()

message = input("Enter message: ")

signature = sign_message(message, private_key)

print("Signature:", signature.hex())

if verify_signature(message, signature, public_key):
    print("Digital Signature is Valid")
else:
    print("Digital Signature is Invalid")