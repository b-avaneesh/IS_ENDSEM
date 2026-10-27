# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


from math import gcd
def keys(p=61,q=53,e=17):
 n=p*q; phi=(p-1)*(q-1)
 if gcd(e,phi)!=1: raise ValueError('e must be coprime with phi(n)')
 return (n,e),(n,pow(e,-1,phi))
def encrypt(text,pub): return [pow(ord(ch),pub[1],pub[0]) for ch in text]
def decrypt(vals,priv): return ''.join(chr(pow(c,priv[1],priv[0])) for c in vals)
if __name__=='__main__':
 pub,priv=keys(); m=input('Message: '); c=encrypt(m,pub); print('Public:',pub,'Ciphertext:',c); print('Decrypted:',decrypt(c,priv))
