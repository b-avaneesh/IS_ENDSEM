def hash_function(text):
    hash_value = 5381

    for ch in text:
        hash_value = hash_value * 33 + ord(ch)

        # Mix the bits
        hash_value = hash_value ^ (hash_value >> 16)

        # Keep it within 32 bits
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


text = input("Enter string: ")

print("Hash value:", hash_function(text))