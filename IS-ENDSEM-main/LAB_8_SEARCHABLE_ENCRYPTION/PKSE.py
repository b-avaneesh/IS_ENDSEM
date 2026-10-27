
import hashlib
from phe import paillier

# 1. Generate public and private keys
public_key, private_key = paillier.generate_paillier_keypair()

# 2. Dataset
documents = {
    "doc1": "python programming language",
    "doc2": "secure data encryption",
    "doc3": "python supports encryption",
    "doc4": "computer networks and security",
    "doc5": "data structures and algorithms",
    "doc6": "searchable encryption system",
    "doc7": "python programming basics",
    "doc8": "secure communication protocols",
    "doc9": "cryptography protects data",
    "doc10": "encryption and security"
}

# Convert words into consistent search tokens
def token(word):
    return hashlib.sha256(word.lower().encode()).hexdigest()

# 3. Create index and encrypt document IDs
def create_index(documents):
    index = {}

    for doc_id, doc in documents.items():
        doc_number = int(doc_id[3:])

        for word in doc.lower().split():
            t = token(word)

            if t not in index:
                index[t] = []

            encrypted_id = public_key.encrypt(doc_number)
            index[t].append(encrypted_id)

    return index

# 4. Search the index
def search(index, query, documents):
    t = token(query)

    if t not in index:
        return []

    results = []

    for encrypted_id in index[t]:
        doc_number = private_key.decrypt(encrypted_id)
        doc_id = "doc" + str(doc_number)
        results.append((doc_id, documents[doc_id]))

    return results


index = create_index(documents)

query = input("Enter search word: ").lower()
results = search(index, query, documents)

if results:
    for doc_id, doc in results:
        print(doc_id, ":", doc)
else:
    print("No matching documents")
