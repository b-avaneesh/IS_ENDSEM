# MODIFICATION:
# affine known-pair recovery. This is a student-friendly addition derived from the official exercise; no source listing was supplied.


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

from string import ascii_lowercase
def additive_candidates(cipher): return [(k,transform(cipher,lambda x:x-k)) for k in range(26)]
def affine_keys(p1,p2,c1,c2):
 out=[]
 for a in range(26):
  if math.gcd(a,26)==1:
   for b in range(26):
    if (a*p1+b)%26==c1 and (a*p2+b)%26==c2: out.append((a,b))
 return out
if __name__=='__main__':
 c=input('Additive ciphertext: ')
 for k,p in additive_candidates(c): print(k,p)
 print('Affine keys for ab -> GL:',affine_keys(0,1,6,11))
