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

def crypt(text,key,decrypt=False):
 if not key.isalpha(): raise ValueError('Keyword must contain letters only')
 shifts=[ord(c.lower())-97 for c in key]; j=0; out=[]
 for ch in text:
  if ch.isalpha():
   s=shifts[j%len(shifts)]*(-1 if decrypt else 1); out.append(transform(ch,lambda x:x+s)); j+=1
  else: out.append(ch)
 return ''.join(out)
if __name__=='__main__':
 m=input('Message: '); k=input('Keyword: '); c=crypt(m,k); print('Ciphertext:',c); print('Decrypted:',crypt(c,k,True))
