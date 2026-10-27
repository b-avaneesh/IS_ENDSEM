"""Menu-driven client for the University Results lab demonstration."""
import hashlib
import json
import socket

HOST, PORT = "127.0.0.1", 5102


def digest_text(text):
    return hashlib.sha1(text.encode()).hexdigest()


def send_json(stream, obj):
    stream.write((json.dumps(obj) + "\n").encode())
    stream.flush()


def recv_json(stream):
    line = stream.readline()
    return json.loads(line.decode()) if line else None


def choose_user():
    # Demo accounts only; the server still enforces each selected user's role.
    users = {
        "1": ("admin", "admin123"),
        "2": ("writer", "write123"),
        "3": ("reader", "read123"),
        "4": ("auditor", "audit123"),
    }
    while True:
        print("\nCHOOSE USER")
        print("1. Admin   - all actions")
        print("2. Writer  - upload, read, search and cipher demonstrations")
        print("3. Reader  - search and list document IDs")
        print("4. Auditor - verify documents, list IDs and view audit logs")
        print("0. Exit")
        choice = input("Select user (0-4): ").strip()
        if choice == "0":
            return None
        if choice in users:
            return users[choice]
        print("Please enter a number from 0 to 4.")


def required_text(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("This field cannot be empty. Please try again.")


def document_id():
    while True:
        value = required_text("Document ID (example: R101): ")
        if len(value.encode("utf-8")) <= 64:
            return value
        print("Document ID must be no more than 64 bytes. Try a shorter ID.")


def integer_input(prompt):
    while True:
        try:
            value = int(input(prompt))
            if value >= 0:
                return value
        except ValueError:
            pass
        print("Enter a nonnegative whole number, such as 7.")


def user_session(username, password):
    with socket.create_connection((HOST, PORT)) as sock, sock.makefile("rwb") as stream:
        send_json(stream, {"username": username, "password": password})
        response = recv_json(stream)
        if not response or response.get("status") != "ok":
            print("Unable to select this user:", response)
            return
        print("\nSelected user:", username)
        while True:
            print("\n1. Upload result document (admin/writer)")
            print("2. Get/decrypt document (admin/writer)")
            print("3. Search one keyword (admin/writer/reader)")
            print("4. List document IDs (all users)")
            print("5. View audit log (admin/auditor)")
            print("6. Verify document (admin/auditor)")
            print("7. Additive cipher: encrypt/decrypt text (admin/writer)")
            print("8. RSA homomorphic multiplication: two integers (admin/writer)")
            print("9. Change user")
            print("0. Exit")
            choice = input("Select action (0-9): ").strip()
            if choice in ("0", "9"):
                send_json(stream, {"action": "quit"})
                return choice == "9"
            if choice == "1":
                print("\nUPLOAD RESULT DOCUMENT")
                print("Type the result as one line of text; do not enter a file path.")
                req = {"action": "upload", "report_id": document_id(),
                       "content": required_text("Result text (example: Alice algebra 85 passed): ")}
            elif choice in ("2", "6"):
                print("\n" + ("GET / DECRYPT DOCUMENT" if choice == "2" else "VERIFY DOCUMENT"))
                req = {"action": "get" if choice == "2" else "verify", "report_id": document_id()}
            elif choice == "3":
                req = {"action": "search", "query": required_text("One search keyword (example: algebra): ")}
            elif choice in ("4", "5"):
                req = {"action": "list" if choice == "4" else "audit"}
            elif choice == "7":
                print("\nADDITIVE CIPHER - fixed shift key: 20")
                req = {"action": "classical", "text": required_text("Text to encrypt (English letters; example: HELLO): ")}
            elif choice == "8":
                print("\nRSA HOMOMORPHIC MULTIPLICATION")
                print("Enter two nonnegative integers. Example: 7 and 3 gives 21.")
                req = {"action": "homomorphic", "a": integer_input("First integer: "),
                       "b": integer_input("Second integer: ")}
            else:
                print("Please enter a number from 0 to 9.")
                continue
            send_json(stream, req)
            response = recv_json(stream)
            if response is None:
                print("Server closed the connection.")
                return
            print(json.dumps(response, indent=2))
            if response.get("status") == "ok" and "content" in response:
                print("Client hash check:", digest_text(response["content"]) == response["digest"])


def main():
    print("UNIVERSITY RESULTS - COMBO 02")
    while True:
        account = choose_user()
        if account is None:
            break
        try:
            if not user_session(*account):
                break
        except OSError as exc:
            print("Connection failed. Start Combo 02 server.py first.")
            print(exc)
            break


if __name__ == "__main__":
    main()
