# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import hashlib,math,secrets
P=467; G=2
def h(m): return int.from_bytes(hashlib.sha256(m).digest(),'big')
def sign(m,x):
 while True:
  k=secrets.randbelow(P-3)+2
  if math.gcd(k,P-1)==1: break
 r=pow(G,k,P); s=((h(m)-x*r)*pow(k,-1,P-1))%(P-1); return r,s
def verify(m,sig,y):
 r,s=sig; return 0<r<P and pow(G,h(m),P)==(pow(y,r,P)*pow(r,s,P))%P
if __name__=='__main__':
 x=127;y=pow(G,x,P);m=input('Message: ').encode();s=sign(m,x);print('Signature:',s,'Valid:',verify(m,s,y),'Tampered:',verify(m+b'!',s,y))
