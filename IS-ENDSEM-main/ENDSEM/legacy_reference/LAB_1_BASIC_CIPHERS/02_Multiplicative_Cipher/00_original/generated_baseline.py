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

def check(k):
 if math.gcd(k,26)!=1: raise ValueError('Key must be coprime with 26')
def encrypt(text,key): check(key); return transform(text,lambda x:key*x)
def decrypt(text,key): check(key); inv=pow(key,-1,26); return transform(text,lambda x:inv*x)
if __name__=='__main__':
 m=input('Message: '); k=int(input('Key: ')); c=encrypt(m,k); print('Ciphertext:',c); print('Decrypted:',decrypt(c,k))
