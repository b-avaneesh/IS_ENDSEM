import socket

p = 23
g = 5

# Alice's private key
a = 6

# Alice's public value
A = pow(g, a, p)

client = socket.socket()
client.connect(("localhost", 5000))

# Receive Bob's public value
B = int(client.recv(1024).decode())

# Send Alice's public value
client.send(str(A).encode())

# Calculate shared secret
shared_secret = pow(B, a, p)

print("Client Public Value:", A)
print("Client Shared Secret:", shared_secret)

client.close()