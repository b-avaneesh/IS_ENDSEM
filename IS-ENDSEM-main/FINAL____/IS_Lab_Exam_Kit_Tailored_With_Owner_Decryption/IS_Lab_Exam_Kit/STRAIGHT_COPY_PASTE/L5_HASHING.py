"""Custom, MD5, SHA-1 and SHA-256 hashing - copy this file."""

import hashlib


def custom_hash(data):
    value = 5381
    for character in data:
        value = (value * 33 + ord(character)) & 0xFFFFFFFF
        value = (value ^ (value >> 13)) & 0xFFFFFFFF
    return value


def hash_data(data, algorithm="sha256"):
    if algorithm.lower() == "custom":
        return custom_hash(data)
    name = algorithm.lower().replace("-", "")
    return hashlib.new(name, data.encode()).hexdigest()


def verify_hash(data, expected_hash, algorithm="sha256"):
    return hash_data(data, algorithm) == expected_hash


if __name__ == "__main__":
    data = input("Enter data: ")
    for algorithm in ["custom", "md5", "sha1", "sha256"]:
        value = hash_data(data, algorithm)
        print(algorithm, ":", value)
        print("Verified:", verify_hash(data, value, algorithm))

