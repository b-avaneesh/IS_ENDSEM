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

def encrypt(text,seed):
 letters=[ord(c.lower())-97 for c in text if c.isalpha()]; keys=[seed%26]+letters; j=0; out=[]
 for ch in text:
  if ch.isalpha(): out.append(transform(ch,lambda x:x+keys[j])); j+=1
  else: out.append(ch)
 return ''.join(out)
def decrypt(text,seed):
 recovered=[]; out=[]
 for ch in text:
  if ch.isalpha():
   key=seed%26 if not recovered else recovered[-1]; p=(ord(ch.lower())-97-key)%26; recovered.append(p); out.append(chr((65 if ch.isupper() else 97)+p))
  else: out.append(ch)
 return ''.join(out)
if __name__=='__main__':
 m=input('Message: '); k=int(input('Seed: ')); c=encrypt(m,k); print('Ciphertext:',c); print('Decrypted:',decrypt(c,k))
