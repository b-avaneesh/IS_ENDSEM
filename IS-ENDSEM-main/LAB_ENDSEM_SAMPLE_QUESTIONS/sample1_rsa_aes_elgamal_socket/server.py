
import socket, json, hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

HOST, PORT = "127.0.0.1", 5000

users = {
    "admin": ["admin123", "admin"],
    "alice": ["alice123", "user"],
    "bob": ["bob123", "user"]
}

documents = {}
logs = []

P, G, X = 467, 2, 127
Y = pow(G, X, P)


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
    # Generate server RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print("Server waiting for clients...")

    while True:
        conn, addr = server.accept()
        print("Connected:", addr)

        try:
            # Send RSA public key to client
            send_data(conn, {"public_key": public_pem})

            # Login
            login = receive_data(conn)

            if not login:
                conn.close()
                continue

            username = login["username"]
            password = login["password"]

            if username not in users or users[username][0] != password:
                send_data(conn, {
                    "status": "error",
                    "message": "Invalid login"
                })
                conn.close()
                continue

            role = users[username][1]

            send_data(conn, {
                "status": "ok",
                "role": role
            })

            logs.append(username + " logged in")
            print(username, "logged in as", role)

            while True:
                req = receive_data(conn)

                if not req:
                    break

                action = req["action"]

                # Role-based access control
                if action in ["upload", "view"]:
                    allowed = True
                elif action in ["delete", "audit"] and role == "admin":
                    allowed = True
                else:
                    allowed = False

                if not allowed:
                    send_data(conn, {
                        "status": "error",
                        "message": "Permission denied"
                    })
                    logs.append(username + " denied " + action)
                    continue

                # UPLOAD
                if action == "upload":
                    try:
                        # Convert HEX strings back to bytes
                        encrypted_key = bytes.fromhex(req["key"])
                        iv = bytes.fromhex(req["iv"])
                        ciphertext = bytes.fromhex(req["ciphertext"])

                        # RSA decrypts AES key
                        aes_key = private_key.decrypt(
                            encrypted_key,
                            padding.OAEP(
                                mgf=padding.MGF1(
                                    algorithm=hashes.SHA256()
                                ),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )

                        # AES-CBC decrypts document
                        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                        message = unpad(
                            cipher.decrypt(ciphertext),
                            AES.block_size
                        ).decode()

                        # Verify SHA-512 hash
                        actual_hash = hashlib.sha512(
                            message.encode()
                        ).hexdigest()

                        hash_ok = actual_hash == req["hash"]

                        # Verify ElGamal signature
                        r = int(req["signature"][0])
                        s = int(req["signature"][1])
                        h = int(actual_hash, 16) % (P - 1)

                        signature_ok = (
                            0 < r < P and 0 <= s < P - 1 and
                            pow(G, h, P) ==
                            (pow(Y, r, P) * pow(r, s, P)) % P
                        )

                        if hash_ok and signature_ok:
                            name = req["name"]
                            documents[name] = message
                            logs.append(username + " uploaded " + name)

                            send_data(conn, {
                                "status": "ok",
                                "message": "Upload successful",
                                "hash_valid": True,
                                "signature_valid": True
                            })
                        else:
                            send_data(conn, {
                                "status": "error",
                                "message": "Verification failed",
                                "hash_valid": hash_ok,
                                "signature_valid": signature_ok
                            })

                    except Exception:
                        send_data(conn, {
                            "status": "error",
                            "message": "Upload failed"
                        })

                # VIEW DOCUMENT NAMES
                elif action == "view":
                    send_data(conn, {
                        "status": "ok",
                        "documents": list(documents.keys())
                    })

                # DELETE DOCUMENT (ADMIN ONLY)
                elif action == "delete":
                    name = req["name"]

                    if name in documents:
                        del documents[name]
                        logs.append(username + " deleted " + name)

                        send_data(conn, {
                            "status": "ok",
                            "message": "Document deleted"
                        })
                    else:
                        send_data(conn, {
                            "status": "error",
                            "message": "Document not found"
                        })

                # AUDIT LOGS (ADMIN ONLY)
                elif action == "audit":
                    send_data(conn, {
                        "status": "ok",
                        "logs": logs
                    })

                # LOGOUT
                elif action == "logout":
                    send_data(conn, {
                        "status": "ok",
                        "message": "Logged out"
                    })
                    break

                else:
                    send_data(conn, {
                        "status": "error",
                        "message": "Unknown action"
                    })

        except Exception as error:
            print("Error:", error)

        finally:
            conn.close()


if __name__ == "__main__":
    main()
