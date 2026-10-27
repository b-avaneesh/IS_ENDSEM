# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import secrets
def keygen(p=7919,g=2,x=2999): return (p,g,pow(g,x,p)),x
def encrypt(text,pub):
 p,g,y=pub; out=[]
 for ch in text:
  k=secrets.randbelow(p-3)+2; out.append((pow(g,k,p),ord(ch)*pow(y,k,p)%p))
 return out
def decrypt(vals,p,x): return ''.join(chr(c2*pow(pow(c1,x,p),-1,p)%p) for c1,c2 in vals)
if __name__=='__main__':
 pub,x=keygen(); m=input('Message: '); c=encrypt(m,pub); print('Ciphertext:',c); print('Decrypted:',decrypt(c,pub[0],x))
