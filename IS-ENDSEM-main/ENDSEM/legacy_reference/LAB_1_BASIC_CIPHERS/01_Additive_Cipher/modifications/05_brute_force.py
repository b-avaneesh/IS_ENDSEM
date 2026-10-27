def decrypt(text, key):
    result = ""

    for ch in text:
        if ch.isupper():
            c = ord(ch) - ord('A')
            p = (c - key) % 26
            result += chr(p + ord('A'))

        elif ch.islower():
            c = ord(ch) - ord('a')
            p = (c - key) % 26
            result += chr(p + ord('a'))

        else:
            result += ch

    return result


ciphertext = input("Enter ciphertext: ")

for key in range(26):
    print("Key", key, ":", decrypt(ciphertext, key))