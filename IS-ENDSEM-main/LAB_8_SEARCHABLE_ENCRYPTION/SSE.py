import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# 1. Encryption and decryption using AES
def encrypt(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), 16))
    return iv, ciphertext

def decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    return plaintext.decode()

# Create a searchable token for each word
def token(key, word):
    return hmac.new(key, word.lower().encode(),
                    hashlib.sha256).digest()

# 2. Create and encrypt the inverted index
def create_index(documents, key):
    index = {}

    for doc_id, doc in documents.items():
        for word in doc.lower().split():
            t = token(key, word)

            if t not in index:
                index[t] = []

            iv, enc_id = encrypt(key, doc_id)
            index[t].append((iv, enc_id))

    return index

# 3. Search the encrypted index
def search(index, query, key, documents):
    t = token(key, query)

    if t not in index:
        return []

    results = []

    for iv, enc_id in index[t]:
        doc_id = decrypt(key, iv, enc_id)
        results.append((doc_id, documents[doc_id]))

    return results

# 4. Dataset: 10 documents
documents = {
    "doc1": "this is a document with some words",
    "doc2": "another document with different words",
    "doc3": "python is a programming language",
    "doc4": "encryption protects sensitive data",
    "doc5": "secure data requires encryption",
    "doc6": "searchable encryption searches documents",
    "doc7": "python supports cryptographic algorithms",
    "doc8": "aes encrypts data using a secret key",
    "doc9": "hashing creates a fixed size digest",
    "doc10": "secure search finds matching words"
}

key = get_random_bytes(16)

# Build the encrypted index
encrypted_index = create_index(documents, key)

# Take search query from user
query = input("Enter word to search: ").lower()

# Display matching documents
results = search(encrypted_index, query, key, documents)

if results:
    for doc_id, doc in results:
        print(doc_id, ":", doc)
else:
    print("No matching documents found")
