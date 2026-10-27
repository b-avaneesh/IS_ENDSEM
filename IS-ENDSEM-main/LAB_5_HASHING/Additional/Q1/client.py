import socket
def hash_function(text):

    hash_value = 5381

    for ch in text:
        hash_value = hash_value * 33 + ord(ch)

        hash_value = hash_value ^ (hash_value >> 16)

        hash_value = hash_value & 0xFFFFFFFF

    return hash_value

client = socket.socket()

client.connect(("localhost", 5000))
n= int(input("Enter number of parts"))
message=''
while n>0:
    part = input("Enter message: ")
    message=message+part
    client.send(part.encode())
    n=n-1
client.shutdown(socket.SHUT_WR)
original_hash = hash_function(message)


server_hash = int(client.recv(1024).decode())

print("Original hash: ", original_hash)
print("Received hash: ", server_hash)

#verify integrity:

if original_hash == server_hash:
    print("Data is not corrupted")
else:
    print("Data is corrupted or modified")

client.close()