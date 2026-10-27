"""Run server.py in another terminal first. Local exam demonstration only."""
import hashlib
import json
import socket

HOST, PORT = "127.0.0.1", 5122

def digest_text(text):
    return hashlib.sha1(text.encode()).hexdigest()

def send_json(stream, obj):
    stream.write((json.dumps(obj) + "\n").encode())
    stream.flush()

def recv_json(stream):
    line = stream.readline()
    return json.loads(line.decode()) if line else None

def main():
    print("Energy Meter Records")
    print("Demo accounts: admin/admin123, writer/write123, reader/read123, auditor/audit123")
    username, password = input("Username: ").strip(), input("Password: ")
    with socket.create_connection((HOST, PORT)) as sock, sock.makefile("rwb") as stream:
        send_json(stream, {"username": username, "password": password})
        response = recv_json(stream)
        print(response)
        if not response or response.get("status") != "ok":
            return
        while True:
            print("\n1 Upload document (admin/writer)\n2 Get/decrypt (admin/writer)")
            print("3 Search one word\n4 List IDs\n5 Audit log (admin/auditor)")
            print("6 Verify (admin/auditor)\n7 Playfair demo (admin/writer)")
            print("8 Paillier demo (admin/writer)\n0 Quit")
            choice = input("Choice: ").strip()
            if choice == "0":
                send_json(stream, {"action": "quit"})
                break
            if choice == "1":
                req = {"action": "upload", "report_id": input("Document ID: ").strip(),
                       "content": input("Document text: ")}
            elif choice in ("2", "6"):
                req = {"action": "get" if choice == "2" else "verify", "report_id": input("Document ID: ").strip()}
            elif choice == "3":
                req = {"action": "search", "query": input("Search word: ")}
            elif choice in ("4", "5"):
                req = {"action": "list" if choice == "4" else "audit"}
            elif choice == "7":
                req = {"action": "classical", "text": input("Text (English letters for Lab 1): ")}
            elif choice == "8":
                try:
                    req = {"action": "homomorphic", "a": int(input("First integer (try 7): ")),
                           "b": int(input("Second integer (try 3): "))}
                except ValueError:
                    print("Enter integers.")
                    continue
            else:
                print("Invalid choice")
                continue
            send_json(stream, req)
            response = recv_json(stream)
            print(json.dumps(response, indent=2))
            if response and response.get("status") == "ok" and "content" in response:
                print("Client hash check:", digest_text(response["content"]) == response["digest"])

if __name__ == "__main__":
    main()

