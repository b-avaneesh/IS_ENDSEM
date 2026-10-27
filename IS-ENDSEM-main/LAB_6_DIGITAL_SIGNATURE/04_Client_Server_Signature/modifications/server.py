import socket

p = 23
g = 5

# Bob's private key
b = 15

# Bob's public value
B = pow(g, b, p)

server = socket.socket()
server.bind(("localhost", 5000))
server.listen(1)

print("Waiting for client...")

conn, addr = server.accept()
print("Client connected")

# Send Bob's public value
conn.send(str(B).encode())

# Receive Alice's public value
A = int(conn.recv(1024).decode())

# Calculate shared secret
shared_secret = pow(A, b, p)

print("Server Public Value:", B)
print("Server Shared Secret:", shared_secret)

conn.close()
server.close()