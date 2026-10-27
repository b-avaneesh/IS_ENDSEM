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

def check(a):
 if math.gcd(a,26)!=1: raise ValueError('Multiplicative key must be coprime with 26')
def encrypt(text,a,b): check(a); return transform(text,lambda x:a*x+b)
def decrypt(text,a,b): check(a); ai=pow(a,-1,26); return transform(text,lambda x:ai*(x-b))
if __name__=='__main__':
 m=input('Message: '); a=int(input('a: ')); b=int(input('b: ')); c=encrypt(m,a,b); print('Ciphertext:',c); print('Decrypted:',decrypt(c,a,b))
