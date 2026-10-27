import socket


def hash_function(text):
 hash_value = 5381

 for ch in text:

  hash_value = hash_value * 33 + ord(ch)

  hash_value = hash_value ^ (hash_value >> 16)

  hash_value = hash_value & 0xFFFFFFFF

 return hash_value


server = socket.socket()

server.bind(("localhost", 5000))
server.listen(1)

print("Waiting for client...")

con,addr = server.accept()


print("Client connected")

data = con.recv(1024).decode()

print("Received: ", data)

hash_value = hash_function(data)

print("Hash: ", hash_value)

con.send(str(hash_value).encode())

con.close()

server.close()