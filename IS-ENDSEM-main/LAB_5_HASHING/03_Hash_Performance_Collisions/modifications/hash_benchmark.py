import hashlib
import random
import string
import time


# Generate random strings
def generate_strings(n):
    data = []

    for i in range(n):
        length = random.randint(10, 20)
        text = ''.join(random.choices(string.ascii_letters, k=length))
        data.append(text)

    return data


#detect collisions:
def check_collisions(hashes):
    seen = set()
    collisions = 0
    for h in hashes:
        if h in seen:
            collisions+=1
        else:
            seen.add(h)
    return collisions


#hash using a particular algorithm:

def test_hash(data, algorithm):
    hashes = []

    start = time.perf_counter()
    for text in data:
        if algorithm == "MD5":
            h = hashlib.md5(text.encode()).hexdigest()
        elif algorithm == "SHA-1":
            h = hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == "SHA-256":
            h = hashlib.sha256(text.encode()).hexdigest()
        hashes.append(h)
    end = time.perf_counter()

    time_taken = end - start
    collisions = check_collisions(hashes)

    return time_taken, collisions

# Main
n = int(input("Enter number of strings (50-100): "))

if n < 50 or n > 100:
    print("Enter a value between 50 and 100.")
else:
    data = generate_strings(n)

    for algorithm in ["MD5", "SHA-1", "SHA-256"]:
        time_taken, collisions = test_hash(data, algorithm)

        print("\n", algorithm)
        print("Time taken:", time_taken, "seconds")
        print("Collisions:", collisions)