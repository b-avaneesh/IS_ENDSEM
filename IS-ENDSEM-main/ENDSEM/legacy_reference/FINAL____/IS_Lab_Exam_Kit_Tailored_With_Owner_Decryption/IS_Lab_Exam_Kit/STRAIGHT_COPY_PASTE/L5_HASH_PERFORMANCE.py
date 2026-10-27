"""MD5/SHA-1/SHA-256 performance and collision check - copy this file."""

import hashlib
import random
import string
import time


def hash_data(data, algorithm="sha256"):
    return hashlib.new(algorithm.replace("-", ""), data.encode()).hexdigest()


def verify_hash(data, expected_hash, algorithm="sha256"):
    return hash_data(data, algorithm) == expected_hash


def random_data(count=100):
    return ["".join(random.choices(string.ascii_letters, k=20)) for _ in range(count)]


if __name__ == "__main__":
    messages = random_data(100)  # EDIT only 100 if another count is asked.
    for algorithm in ["md5", "sha1", "sha256"]:
        start = time.perf_counter()
        hashes = [hash_data(message, algorithm) for message in messages]
        elapsed = time.perf_counter() - start
        collisions = len(hashes) - len(set(hashes))
        print(algorithm, "time:", elapsed)
        print(algorithm, "collisions:", collisions)
