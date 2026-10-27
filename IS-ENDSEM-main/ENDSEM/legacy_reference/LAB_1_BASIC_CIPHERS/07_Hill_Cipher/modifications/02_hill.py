# MODIFICATION:
# validate invertible key. This is a student-friendly addition derived from the official exercise; no source listing was supplied.


import math
def inv2(k):
 d=(k[0][0]*k[1][1]-k[0][1]*k[1][0])%26
 if math.gcd(d,26)!=1: raise ValueError('Key matrix is not invertible modulo 26')
 di=pow(d,-1,26); return [[k[1][1]*di%26,-k[0][1]*di%26],[-k[1][0]*di%26,k[0][0]*di%26]]
def crypt(text,k):
 s=''.join(c for c in text.lower() if c.isalpha()); s += 'x'*(len(s)%2); out=''
 for i in range(0,len(s),2):
  a,b=ord(s[i])-97,ord(s[i+1])-97; out+=chr(97+(k[0][0]*a+k[0][1]*b)%26)+chr(97+(k[1][0]*a+k[1][1]*b)%26)
 return out
if __name__=='__main__':
 k=[[3,3],[2,7]]; m=input('Message: '); c=crypt(m,k); print('Ciphertext:',c); print('Decrypted:',crypt(c,inv2(k)))
