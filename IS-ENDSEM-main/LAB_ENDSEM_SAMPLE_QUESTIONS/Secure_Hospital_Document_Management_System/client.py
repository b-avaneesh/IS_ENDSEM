import json
import socket

HOST, PORT = "127.0.0.1", 5000


def send_json(stream, obj):
    stream.write((json.dumps(obj) + "\n").encode("utf-8"))
    stream.flush()


def recv_json(stream):
    line = stream.readline()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def main():
    username = input("Username: ").strip()
    password = input("Password: ")
    with socket.create_connection((HOST, PORT)) as sock, sock.makefile("rwb") as stream:
        send_json(stream, {"username": username, "password": password})
        response = recv_json(stream)
        print(response)
        if not response or response.get("status") != "ok":
            return

        role = response["role"]
        print("Logged in as:", role)
        while True:
            print("\n1 Upload report (doctor/admin)")
            print("2 Get/decrypt report (doctor/admin)")
            print("3 Search reports (doctor/admin/receptionist)")
            print("4 List report IDs")
            print("5 View audit log (admin/auditor)")
            print("6 Verify report (auditor)")
            print("7 Vigenere encrypt (doctor/admin)")
            print("8 Paillier homomorphic addition (doctor/admin)")
            print("0 Quit")
            choice = input("Choice: ").strip()

            if choice == "0":
                send_json(stream, {"action": "quit"})
                break
            elif choice == "1":
                req = {"action": "upload", "report_id": input("Report ID (e.g. R101): ").strip(),
                       "content": input("Report text: ")}
            elif choice == "2":
                req = {"action": "get", "report_id": input("Report ID: ").strip()}
            elif choice == "3":
                req = {"action": "search", "query": input("Search word: ").strip()}
            elif choice == "4":
                req = {"action": "list"}
            elif choice == "5":
                req = {"action": "audit"}
            elif choice == "6":
                req = {"action": "verify", "report_id": input("Report ID: ").strip()}
            elif choice == "7":
                req = {"action": "vigenere", "text": input("Text: "), "key": input("Alphabetic key: ")}
            elif choice == "8":
                req = {"action": "paillier_add", "a": int(input("First integer: ")),
                       "b": int(input("Second integer: "))}
            else:
                print("Invalid choice")
                continue

            send_json(stream, req)
            print(json.dumps(recv_json(stream), indent=2))


if __name__ == "__main__":
    main()
