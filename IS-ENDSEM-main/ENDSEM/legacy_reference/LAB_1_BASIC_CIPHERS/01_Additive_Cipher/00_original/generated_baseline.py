# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import math
ABC = 'abcdefghijklmnopqrstuvwxyz'
def transform(text, fn):
    out=[]
    for ch in text:
        if ch.isalpha():
            base=ord('A') if ch.isupper() else ord('a')
            out.append(chr(base+fn(ord(ch.lower())-97)%26))
        else: out.append(ch)
    return ''.join(out)

def encrypt(text,key): return transform(text,lambda x:x+key)
def decrypt(text,key): return transform(text,lambda x:x-key)
if __name__=='__main__':
 m=input('Message: '); k=int(input('Key (0-25): ')); c=encrypt(m,k); print('Ciphertext:',c); print('Decrypted:',decrypt(c,k))
