# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import time
class RabinKMS:
 def __init__(self): self.facilities={}; self.audit=[]
 def generate(self,name,p=499,q=547):
  if p%4!=3 or q%4!=3: raise ValueError('p and q must be 3 mod 4')
  self.facilities[name]={'public':p*q,'private':(p,q),'revoked':False}; self.audit.append(('generate',name,time.time())); return p*q
 def encrypt(self,m,name): return m*m%self.facilities[name]['public']
 def revoke(self,name): self.facilities[name]['revoked']=True; self.audit.append(('revoke',name,time.time()))
if __name__=='__main__':
 k=RabinKMS(); n=k.generate('Clinic-A'); print('Public n:',n,'Ciphertext for 42:',k.encrypt(42,'Clinic-A')); k.revoke('Clinic-A'); print('Audit events:',len(k.audit))
