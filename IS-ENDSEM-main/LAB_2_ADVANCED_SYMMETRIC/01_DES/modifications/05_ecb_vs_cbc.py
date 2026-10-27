from Crypto.Cipher import DES
from Crypto.Util.Padding import pad


key = b"A1B2C3D4"
iv = b"12345678"

plaintext = input("Enter plaintext: ")

data = pad(
    plaintext.encode(),
    DES.block_size
)


# ECB
ecb = DES.new(
    key,
    DES.MODE_ECB
)

ecb_ciphertext = ecb.encrypt(data)


# CBC
cbc = DES.new(
    key,
    DES.MODE_CBC,
    iv=iv
)

cbc_ciphertext = cbc.encrypt(data)


print("ECB Ciphertext:")
print(ecb_ciphertext.hex())

print("\nCBC Ciphertext:")
print(cbc_ciphertext.hex())