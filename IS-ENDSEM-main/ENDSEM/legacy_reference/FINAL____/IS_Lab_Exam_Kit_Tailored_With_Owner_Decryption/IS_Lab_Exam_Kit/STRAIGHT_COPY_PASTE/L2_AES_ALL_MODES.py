"""AES ECB/CBC/CFB/OFB/CTR - copy this complete file. Requires PyCryptodome."""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def make_key(key_text):
    return key_text.encode()[:16].ljust(16, b"0")


def encrypt_data(data, key, mode="CBC"):
    key, mode = make_key(key), mode.upper()
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return {"data": cipher.encrypt(pad(data.encode(), 16))}
    if mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR)
        return {"data": cipher.encrypt(data.encode()), "nonce": cipher.nonce}
    mode_value = {"CBC": AES.MODE_CBC, "CFB": AES.MODE_CFB, "OFB": AES.MODE_OFB}[mode]
    cipher = AES.new(key, mode_value, iv=get_random_bytes(16))
    message = pad(data.encode(), 16) if mode == "CBC" else data.encode()
    return {"data": cipher.encrypt(message), "iv": cipher.iv}


def decrypt_data(encrypted_data, key, mode="CBC"):
    key, mode = make_key(key), mode.upper()
    if mode == "ECB":
        plain = AES.new(key, AES.MODE_ECB).decrypt(encrypted_data["data"])
        return unpad(plain, 16).decode()
    if mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=encrypted_data["nonce"])
        return cipher.decrypt(encrypted_data["data"]).decode()
    mode_value = {"CBC": AES.MODE_CBC, "CFB": AES.MODE_CFB, "OFB": AES.MODE_OFB}[mode]
    cipher = AES.new(key, mode_value, iv=encrypted_data["iv"])
    plain = cipher.decrypt(encrypted_data["data"])
    return (unpad(plain, 16) if mode == "CBC" else plain).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter AES key: ")
    for mode in ["ECB", "CBC", "CFB", "OFB", "CTR"]:
        encrypted = encrypt_data(data, key, mode)
        print(mode, "hex:", encrypted["data"].hex())
        print(mode, "decrypted:", decrypt_data(encrypted, key, mode))
