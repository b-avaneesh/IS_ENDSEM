import socket, json, hashlib, secrets, math

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST, PORT = "127.0.0.1", 5000
P, G, X = 467, 2, 127


def send_data(conn, data):
    conn.sendall((json.dumps(data) + "\n").encode())


def receive_data(conn):
    data = ""
    while True:
        ch = conn.recv(1).decode()
        if ch == "":
            return None
        if ch == "\n":
            break
        data += ch
    return json.loads(data)

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    # Receive server's RSA public key
    first = receive_data(client)
    server_public_key = serialization.load_pem_public_key(first["public_key"].encode())

    # Login
    username = input("Username: ")
    password = input("password: ")

    send_data(client, {"username": username, "password": password})

    result = receive_data(client)
    print(result)

    if result["status"] != "ok":
        client.close()
        return

    print("Logged in as: ", result["role"])

    while True:
        print("\n1 Upload 2 view 3 Delete 4 Audit logs 5 logout")
        choice = input("Choose: ")

        if choice == "1":
            name = input("Document name: ")
            message = input("Document text: ")

            #encrypt message using aes 256:
            aes_key, iv = secrets.token_bytes(32), secrets.token_bytes(16) #aes 256 key and 16 bytes nonce
            # Create AES cipher
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            # Encrypt using aes 256
            ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

            #encrypt aes key using rsa:
            encrypted_key = server_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            #digest calculation:
            digest = hashlib.sha512(message.encode()).hexdigest()

            #elgamal signature:
            k = 61  # gcd(k, p-1) = 1
            h = int(digest, 16) % (P - 1)
            r = pow(G, k, P)
            k_inverse = pow(k, -1, P - 1)
            s = (k_inverse * (h - X * r)) % (P - 1)

            send_data(client,
                {
                    "action": "upload",
                    "name": name,
                    "key": encrypted_key.hex(),
                    "iv": iv.hex(),
                    "ciphertext": ciphertext.hex(),
                    "hash": digest,
                    "signature": [r,s]
                }
            )
            print(receive_data(client))

        elif choice == "2":
            send_data(client, {"action": "view"})
            print(receive_data(client))
        elif choice == "3":
            name = input("Document name to delete: ")
            send_data(client, {"action": "delete", "name": name})
            print(receive_data(client))
        elif choice == "4":
            send_data(client, {"action": "audit"})
            print(receive_data(client))
        elif choice == "5":
            send_data(client, {"action": "logout"})
            print(receive_data(client))
            break
        else:
            print("Invalid choice")

    client.close()
if __name__ == "__main__":
    main()



