# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


def square(key):
 s=[]
 for c in (key+'abcdefghiklmnopqrstuvwxyz').lower():
  c='i' if c=='j' else c
  if c.isalpha() and c not in s:s.append(c)
 return s
def pairs(text):
 s=''.join('i' if c=='j' else c for c in text.lower() if c.isalpha()); out=[]; i=0
 while i<len(s):
  a=s[i]; b=s[i+1] if i+1<len(s) else 'x'
  if a==b: b='x'; i+=1
  else:i+=2
  out.append((a,b))
 return out
def crypt(text,key,decrypt=False):
 q=square(key); pos={c:divmod(i,5) for i,c in enumerate(q)}; step=-1 if decrypt else 1; out=[]
 for a,b in pairs(text):
  ra,ca=pos[a]; rb,cb=pos[b]
  if ra==rb: out += [q[ra*5+(ca+step)%5],q[rb*5+(cb+step)%5]]
  elif ca==cb: out += [q[((ra+step)%5)*5+ca],q[((rb+step)%5)*5+cb]]
  else: out += [q[ra*5+cb],q[rb*5+ca]]
 return ''.join(out)
if __name__=='__main__':
 m=input('Message: '); k=input('Key: '); c=crypt(m,k); print('Matrix:',*[' '.join(square(k)[i:i+5]) for i in range(0,25,5)],sep='\n'); print('Ciphertext:',c); print('Raw decrypted:',crypt(c,k,True))
