# MODIFICATION:
# audit communication. This is a student-friendly addition derived from the official exercise; no source listing was supplied.


import secrets
class Registry:
 def __init__(self): self.active=set(); self.audit=[]
 def add(self,name): self.active.add(name); self.audit.append(('add',name))
 def revoke(self,name): self.active.discard(name); self.audit.append(('revoke',name))
 def session(self,a,b,p=7919,g=2):
  if a not in self.active or b not in self.active: raise PermissionError('Inactive subsystem')
  x=secrets.randbelow(p-2)+1; y=secrets.randbelow(p-2)+1; self.audit.append(('session',a,b)); return pow(pow(g,y,p),x,p),pow(pow(g,x,p),y,p)
if __name__=='__main__':
 r=Registry(); [r.add(x) for x in ('Finance','HR','SupplyChain')]; a,b=r.session('Finance','HR'); print('Shared secrets match:',a==b); r.revoke('HR'); print('Audit:',r.audit)
