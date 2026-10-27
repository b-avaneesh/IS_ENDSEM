# Self-contained generated combination; requires cryptography only.
"""Lab building blocks. Educational algorithms; see EXAM_GUIDE.txt for limits."""
import hashlib, hmac, json, math, secrets
from functools import lru_cache
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as ap, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB, OFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB, OFB

ENCRYPTIONS = ['ADDITIVE','MULTIPLICATIVE','AFFINE','VIGENERE','AUTOKEY','PLAYFAIR','HILL','TRANSPOSITION','DES','DES_CBC','TRIPLE_DES','AES_128','AES_192','AES_256','AES_CBC','AES_CFB','AES_OFB','AES_CTR','RSA','RSA_HYBRID','ECC_HYBRID','DIFFIE_HELLMAN_AES','ELGAMAL','RABIN']
HASHES = ['MD5','SHA1','SHA256','SHA512']
SIGNATURES = ['RSA','ELGAMAL','SCHNORR','ECDSA']
HE_SCHEMES = ['NONE','PAILLIER','RSA','ELGAMAL']
SEARCHES = ['NONE','SSE','PAILLIER_PRIVATE_SCAN']

def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def digest(data, name='SHA256'): return hashlib.new(name.lower(),data).digest()
def hash_obj(name): return {'MD5':hashes.MD5,'SHA1':hashes.SHA1,'SHA256':hashes.SHA256,'SHA512':hashes.SHA512}[name]()

# RFC 2409 group 2 prime; textbook group demonstrations, not a new production protocol.
P=int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF',16)
Q=(P-1)//2

class Signer:
    def __init__(self, kind='RSA', hash_name='SHA256'):
        if kind not in SIGNATURES or hash_name not in HASHES:raise ValueError('Unknown signature/hash')
        self.kind,self.hash_name=kind,hash_name
        if kind=='RSA': self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        elif kind=='ECDSA': self.key=ec.generate_private_key(ec.SECP256R1())
        else:
            self.x=secrets.randbelow(Q-2)+1; self.g=4; self.y=pow(self.g,self.x,P)
    def sign(self,data):
        d=digest(data,self.hash_name); z=int.from_bytes(d,'big')
        if self.kind=='RSA': return self.key.sign(d,ap.PKCS1v15(),utils.Prehashed(hash_obj(self.hash_name))).hex()
        if self.kind=='ECDSA': return self.key.sign(d,ec.ECDSA(utils.Prehashed(hash_obj(self.hash_name)))).hex()
        if self.kind=='ELGAMAL':
            k=secrets.randbelow(P-3)+2
            while math.gcd(k,P-1)!=1: k=secrets.randbelow(P-3)+2
            r=pow(self.g,k,P); return [r,((z-self.x*r)*pow(k,-1,P-1))%(P-1)]
        k=secrets.randbelow(Q-1)+1; r=pow(self.g,k,P)
        e=int.from_bytes(digest(canonical([r,d.hex()]),self.hash_name),'big')%Q
        return [e,(k+self.x*e)%Q]
    def verify(self,data,sig):
        try:
            d=digest(data,self.hash_name); z=int.from_bytes(d,'big')
            if self.kind=='RSA': self.key.public_key().verify(bytes.fromhex(sig),d,ap.PKCS1v15(),utils.Prehashed(hash_obj(self.hash_name)))
            elif self.kind=='ECDSA': self.key.public_key().verify(bytes.fromhex(sig),d,ec.ECDSA(utils.Prehashed(hash_obj(self.hash_name))))
            elif self.kind=='ELGAMAL':
                r,s=sig
                return 0<r<P and 0<=s<P-1 and pow(self.g,z,P)==pow(self.y,r,P)*pow(r,s,P)%P
            else:
                e,s=sig
                if not (0<=e<Q and 0<=s<Q): return False
                r=pow(self.g,s,P)*pow(self.y,-e,P)%P
                return e==int.from_bytes(digest(canonical([r,d.hex()]),self.hash_name),'big')%Q
            return True
        except (ValueError,TypeError,OverflowError): return False
        except Exception: return False

class Paillier:
    def __init__(self,bits=1024):
        k=rsa.generate_private_key(public_exponent=65537,key_size=bits).private_numbers()
        self.n=k.p*k.q; self.n2=self.n*self.n; self.g=self.n+1
        self.lam=math.lcm(k.p-1,k.q-1); self.mu=pow(self.lam,-1,self.n)
    def encrypt(self,m):
        if not 0<=m<self.n: raise ValueError('Paillier plaintext must be in [0,n)')
        r=secrets.randbelow(self.n-1)+1
        while math.gcd(r,self.n)!=1:r=secrets.randbelow(self.n-1)+1
        return pow(self.g,m,self.n2)*pow(r,self.n,self.n2)%self.n2
    def decrypt(self,c):
        if not 0<c<self.n2 or math.gcd(c,self.n)!=1:raise ValueError('Invalid Paillier ciphertext')
        return ((pow(c,self.lam,self.n2)-1)//self.n*self.mu)%self.n
    def add(self,*cs): return math.prod(cs)%self.n2
    def scale(self,c,k): return pow(c,k,self.n2)

class Homomorphic:
    def __init__(self,kind):
        self.kind=kind
        if kind=='PAILLIER':self.key=Paillier();self.mod=self.key.n
        elif kind=='RSA':
            k=rsa.generate_private_key(public_exponent=65537,key_size=1024).private_numbers()
            self.mod=k.public_numbers.n;self.e=k.public_numbers.e;self.d=k.d
        elif kind=='ELGAMAL':self.mod=P;self.x=secrets.randbelow(Q-1)+1;self.y=pow(4,self.x,P)
    def encrypt(self,m):
        if not 0<=m<self.mod:raise ValueError('Integer outside plaintext domain')
        if self.kind=='PAILLIER':return self.key.encrypt(m)
        if self.kind=='RSA':return pow(m,self.e,self.mod)
        if m==0:raise ValueError('Use nonzero group elements for ElGamal')
        k=secrets.randbelow(Q-1)+1;return [pow(4,k,P),m*pow(self.y,k,P)%P]
    def decrypt(self,c):
        if self.kind=='PAILLIER':return self.key.decrypt(c)
        if self.kind=='RSA':return pow(c,self.d,self.mod)
        return c[1]*pow(c[0],-self.x,P)%P
    def combine(self,cs):
        if not cs:raise ValueError('No ciphertexts')
        if self.kind=='PAILLIER':return self.key.add(*cs)
        if self.kind=='RSA':return math.prod(cs)%self.mod
        return [math.prod(c[0] for c in cs)%P,math.prod(c[1] for c in cs)%P]

def symmetric(data,key,mode='CBC',decrypt=False,iv=None,des=False):
    alg=TripleDES(key) if des else algorithms.AES(key)
    block=alg.block_size//8
    iv=iv or secrets.token_bytes(block)
    m={'ECB':lambda:modes.ECB(),'CBC':lambda:modes.CBC(iv),'CFB':lambda:CFB(iv),'OFB':lambda:OFB(iv),'CTR':lambda:modes.CTR(iv)}[mode]()
    cipher=Cipher(alg,m)
    if decrypt:
        op=cipher.decryptor();out=op.update(data)+op.finalize()
        if mode in ('ECB','CBC'):
            u=padding.PKCS7(alg.block_size).unpadder();out=u.update(out)+u.finalize()
    else:
        if mode in ('ECB','CBC'):
            p=padding.PKCS7(alg.block_size).padder();data=p.update(data)+p.finalize()
        op=cipher.encryptor();out=op.update(data)+op.finalize()
    return out,iv

def classical(text,kind,decrypt=False):
    """Uppercase alphabet core; envelope encodes bytes to A-P to preserve files exactly."""
    a=[ord(c)-65 for c in text]; sign=-1 if decrypt else 1
    if kind in ('ADDITIVE','MULTIPLICATIVE','AFFINE'):
        mul=5 if kind!='ADDITIVE' else 1;shift=8 if kind!='MULTIPLICATIVE' else 0
        a=[((x-shift)*pow(mul,-1,26) if decrypt else mul*x+shift)%26 for x in a]
    elif kind in ('VIGENERE','AUTOKEY'):
        seed=[ord(c)-65 for c in 'HEALTH'];out=[]
        for i,x in enumerate(a):
            k=seed[i%len(seed)] if kind=='VIGENERE' else (seed[i] if i<len(seed) else (out if decrypt else a)[i-len(seed)])
            out.append((x+sign*k)%26)
        a=out
    elif kind=='HILL':
        if len(a)%2:a.append(23)
        b=(15,17,20,9) if decrypt else (3,3,2,5)
        a=[v for i in range(0,len(a),2) for v in ((b[0]*a[i]+b[1]*a[i+1])%26,(b[2]*a[i]+b[3]*a[i+1])%26)]
    elif kind=='TRANSPOSITION':
        order=[i for k in range(5) for i in range(k,len(a),5)]
        if decrypt:
            out=[0]*len(a)
            for i,x in zip(order,a):out[i]=x
            a=out
        else:a=[a[i] for i in order]
    elif kind=='PLAYFAIR':
        square='MONARCHYBDEFGIKLPQSTUVWXZ';s=text.replace('J','I')
        if not decrypt:
            pairs=[];i=0
            while i<len(s):
                x=s[i];y=s[i+1] if i+1<len(s) else 'X'
                if x==y:y='X';i+=1
                else:i+=2
                pairs.extend([x,y])
            s=''.join(pairs)
        out=''
        for i in range(0,len(s),2):
            r,c=divmod(square.index(s[i]),5);u,v=divmod(square.index(s[i+1]),5)
            if r==u:c=(c+sign)%5;v=(v+sign)%5
            elif c==v:r=(r+sign)%5;u=(u+sign)%5
            else:c,v=v,c
            out+=square[r*5+c]+square[u*5+v]
        return out
    return ''.join(chr(x+65) for x in a)

class Envelope:
    def __init__(self,kind='AES_CBC',rsa_bits=2048):
        if kind not in ENCRYPTIONS:raise ValueError('Unknown encryption')
        self.kind=kind;self.key=secrets.token_bytes(32)
        if kind in ('RSA','RSA_HYBRID'):self.rsa=rsa.generate_private_key(public_exponent=65537,key_size=rsa_bits)
        if kind=='ECC_HYBRID':self.ec=ec.generate_private_key(ec.SECP256R1())
        if kind in ('ELGAMAL','DIFFIE_HELLMAN_AES'):self.eg=Homomorphic('ELGAMAL')
        if kind=='RABIN':
            while True:
                k=rsa.generate_private_key(public_exponent=65537,key_size=1024).private_numbers()
                if k.p%4==k.q%4==3:break
            self.p,self.q=k.p,k.q;self.n=k.p*k.q
    def encrypt(self,data):
        k=self.kind
        if k in ENCRYPTIONS[:8]:
            # Alphabet excludes J and X, so Playfair's J merge/fillers are reversible.
            alphabet='ABCDEFGHIKLMNOPQ';txt=''.join(alphabet[int(c,16)] for c in data.hex())
            return {'text':classical(txt,k),'size':len(data)}
        if k=='RSA':
            chunk=self.rsa.key_size//8-66
            return {'blocks':[self.rsa.public_key().encrypt(data[i:i+chunk],ap.OAEP(mgf=ap.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)).hex() for i in range(0,len(data),chunk)]}
        if k=='ELGAMAL':return {'blocks':[self.eg.encrypt(x+1) for x in data]}
        if k=='RABIN':return {'blocks':[pow((x+1)*65536+0xBEEF,2,self.n) for x in data]}
        key=self.key;extra={};mode='CBC';des=False
        if k=='RSA_HYBRID':
            key=secrets.token_bytes(32);extra['wrapped']=self.rsa.public_key().encrypt(key,ap.OAEP(mgf=ap.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)).hex()
        elif k=='ECC_HYBRID':
            ephemeral=ec.generate_private_key(ec.SECP256R1());key=digest(ephemeral.exchange(ec.ECDH(),self.ec.public_key()))
            extra['ephemeral']=ephemeral.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint).hex()
        elif k=='DIFFIE_HELLMAN_AES':
            a=secrets.randbelow(Q-1)+1;extra['ephemeral']=pow(4,a,P);key=digest(str(pow(self.eg.y,a,P)).encode())
        elif k.startswith('DES') or k=='TRIPLE_DES':
            des=True;key=self.key[:24] if k=='TRIPLE_DES' else self.key[:8]*3;mode='ECB' if k=='DES' else 'CBC'
        elif k in ('AES_128','AES_192','AES_256'):key=self.key[:int(k.split('_')[1])//8];mode='ECB'
        elif k.startswith('AES_'):mode=k[4:];key=self.key
        ct,iv=symmetric(data,key,mode,des=des)
        return dict(ct=ct.hex(),iv=iv.hex(),**extra)
    def decrypt(self,obj):
        k=self.kind
        if k in ENCRYPTIONS[:8]:
            txt=classical(obj['text'],k,True)
            if k=='PLAYFAIR':txt=txt.replace('X','')
            alphabet='ABCDEFGHIKLMNOPQ'
            return bytes.fromhex(''.join(format(alphabet.index(c),'x') for c in txt[:obj['size']*2]))
        if k=='RSA':return b''.join(self.rsa.decrypt(bytes.fromhex(c),ap.OAEP(mgf=ap.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)) for c in obj['blocks'])
        if k=='ELGAMAL':return bytes(self.eg.decrypt(c)-1 for c in obj['blocks'])
        if k=='RABIN':
            out=[]
            for c in obj['blocks']:
                a=pow(c,(self.p+1)//4,self.p);b=pow(c,(self.q+1)//4,self.q)
                roots={(u*self.q*pow(self.q,-1,self.p)+v*self.p*pow(self.p,-1,self.q))%self.n for u in (a,-a) for v in (b,-b)}
                found=[r//65536-1 for r in roots if r%65536==0xBEEF and 1<=r//65536<=256]
                if len(found)!=1:raise ValueError('Ambiguous or invalid Rabin block')
                out+=found
            return bytes(out)
        key=self.key;mode='CBC';des=False
        if k=='RSA_HYBRID':key=self.rsa.decrypt(bytes.fromhex(obj['wrapped']),ap.OAEP(mgf=ap.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        elif k=='ECC_HYBRID':key=digest(self.ec.exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),bytes.fromhex(obj['ephemeral']))))
        elif k=='DIFFIE_HELLMAN_AES':key=digest(str(pow(obj['ephemeral'],self.eg.x,P)).encode())
        elif k.startswith('DES') or k=='TRIPLE_DES':des=True;key=self.key[:24] if k=='TRIPLE_DES' else self.key[:8]*3;mode='ECB' if k=='DES' else 'CBC'
        elif k in ('AES_128','AES_192','AES_256'):key=self.key[:int(k.split('_')[1])//8];mode='ECB'
        elif k.startswith('AES_'):mode=k[4:]
        return symmetric(bytes.fromhex(obj['ct']),key,mode,True,bytes.fromhex(obj['iv']),des)[0]

class SearchIndex:
    """SSE: keyed tokens + encrypted posting lists. Private scan is NOT PEKS."""
    def __init__(self,kind='SSE'):
        self.kind=kind;self.token_key=secrets.token_bytes(32);self.box=Envelope('AES_CBC');self.entries={}
        if kind=='PAILLIER_PRIVATE_SCAN':self.paillier=Paillier()
    def token(self,word):return hmac.new(self.token_key,word.lower().encode(),'sha256').hexdigest()
    def add(self,word,doc_id):
        word=word.lower()
        if self.kind=='SSE':
            token=self.token(word);ids=json.loads(self.box.decrypt(self.entries[token])) if token in self.entries else []
            if doc_id not in ids:ids.append(doc_id)
            self.entries[token]=self.box.encrypt(canonical(ids))
        else:
            h=int.from_bytes(digest(word.encode()),'big')
            self.entries[str(len(self.entries))]=[self.paillier.encrypt(h),self.paillier.encrypt(int(doc_id))]
    def search(self,word):
        if self.kind=='SSE':
            x=self.entries.get(self.token(word));return json.loads(self.box.decrypt(x)) if x else []
        # Authorized private-key holder decrypts differences; server alone cannot compare.
        h=int.from_bytes(digest(word.lower().encode()),'big');query=self.paillier.encrypt(h);p=self.paillier
        return sorted({str(p.decrypt(doc)) for term,doc in self.entries.values() if p.decrypt(term*pow(query,-1,p.n2)%p.n2)==0})

# Shamir 2-of-3 private-key custody demonstration, not distributed Paillier partial decryption.
SHARE_PRIME=2**1279-1
def split_secret(secret):
    if not 0<=secret<SHARE_PRIME:raise ValueError('Secret too large')
    a=secrets.randbelow(SHARE_PRIME)
    return [(i,(secret+a*i)%SHARE_PRIME) for i in (1,2,3)]
def recover_secret(shares):
    if len(shares)<2 or len({x for x,y in shares})!=len(shares):raise ValueError('Need two distinct trustees')
    return sum(y*math.prod(-u for u,v in shares if u!=x)*pow(math.prod(x-u for u,v in shares if u!=x),-1,SHARE_PRIME) for x,y in shares)%SHARE_PRIME

class ThresholdPaillier:
    """3-of-3 additive exponent shares; actual partial decryption, trusted dealer.

    d=lambda*inverse(lambda,n): d=0 mod lambda and d=1 mod n.
    Product c**d_i = c**d; L(c**d) = m mod n. No key reconstruction.
    No malicious-share proofs; trustees simulated in one process for this lab.
    """
    def __init__(self):
        p=Paillier();self.n,self.n2,self.g=p.n,p.n2,p.g
        d=p.lam*p.mu
        a=secrets.randbits(4096);b=secrets.randbits(4096)
        self.trustees={1:a,2:b,3:d-a-b}
        # p and d are not retained; production trustees would be separate machines.
    def encrypt(self,m):return Paillier.encrypt(self,m)
    def add(self,*cs):return math.prod(cs)%self.n2
    def partial(self,c,trustee):
        if not 0<c<self.n2 or math.gcd(c,self.n)!=1:raise ValueError('Invalid ciphertext')
        return pow(c,self.trustees[trustee],self.n2)
    def combine(self,partials):
        if set(partials)!={1,2,3}:raise ValueError('All three distinct trustee partials required')
        u=math.prod(partials.values())%self.n2
        if (u-1)%self.n:raise ValueError('Invalid partial decryption')
        return (u-1)//self.n

"""Configurable menu-driven records system. Run with --help or --demo."""
import argparse, copy, json, sys, time
from pathlib import Path


class RecordSystem:
    def __init__(self,encryption='AES_CBC',hash_name='SHA256',signature='RSA',he='PAILLIER',search='SSE',scenario='records'):
        self.config=dict(encryption=encryption,hash_name=hash_name,signature=signature,he=he,search=search,scenario=scenario)
        self.box=Envelope(encryption);self.users={'alice':('123','owner'),'bob':('123','reviewer'),'carol':('123','auditor'),'eve':('123','owner')}
        self.signers={u:Signer(signature,hash_name) for u in ('alice','eve')}
        self.he=Homomorphic(he) if he!='NONE' else None
        self.index=SearchIndex(search) if search!='NONE' else None
        self.records={};self.revoked=set();self.audit=[]
    def authorize(self,user,roles):
        if user not in self.users or user in self.revoked or self.users[user][1] not in roles:raise PermissionError('Access denied')
    def login(self,user,password):
        if user not in self.users or self.users[user][0]!=password or user in self.revoked:raise PermissionError('Invalid credentials/revoked')
        return user
    def upload(self,user,data,recipient='bob',keywords='record',number=1,expires=None):
        self.authorize(user,{'owner'})
        if recipient not in self.users or self.users[recipient][1]!='reviewer':raise ValueError('Unknown reviewer')
        ident=str(len(self.records)+1);cipher=self.box.encrypt(data);h=self.config['hash_name']
        rec=dict(id=ident,owner=user,recipient=recipient,time=time.time(),expires=expires,cipher=cipher,plain_hash=digest(data,h).hex(),cipher_hash=digest(canonical(cipher),h).hex(),number=self.he.encrypt(number) if self.he else None)
        rec['cipher_signature']=self.signers[user].sign(canonical(cipher))
        rec['signature']=self.signers[user].sign(canonical(rec))
        self.records[ident]={'payload':rec,'status':'PENDING'}
        if self.index:
            for word in set(keywords.lower().split()):self.index.add(word,ident)
        self.audit.append(['UPLOAD',ident,time.time()]);return ident
    def verify(self,ident):
        rec=copy.deepcopy(self.records[ident]['payload']);sig=rec.pop('signature')
        return self.signers[rec['owner']].verify(canonical(rec),sig) and self.signers[rec['owner']].verify(canonical(rec['cipher']),rec['cipher_signature']) and rec['cipher_hash']==digest(canonical(rec['cipher']),self.config['hash_name']).hex()
    def read(self,user,ident):
        self.authorize(user,{'owner','reviewer'});rec=self.records[ident]['payload']
        if user not in (rec['owner'],rec['recipient']):raise PermissionError('Not assigned to you')
        if rec['expires'] is not None and time.time()>rec['expires']:raise PermissionError('Record expired')
        if not self.verify(ident):raise ValueError('Signature/ciphertext integrity failed')
        plain=self.box.decrypt(rec['cipher'])
        if digest(plain,self.config['hash_name']).hex()!=rec['plain_hash']:raise ValueError('Plaintext hash failed')
        self.audit.append(['VERIFIED',ident,time.time()]);return plain
    def metadata(self,user):
        self.authorize(user,{'owner','reviewer','auditor'})
        rows=[]
        for i,r in self.records.items():
            p=r['payload']
            if self.users[user][1]!='auditor' and user not in (p['owner'],p['recipient']):continue
            row=dict(id=i,owner=p['owner'],recipient=p['recipient'],time=p['time'],plain_hash=p['plain_hash'],cipher_hash=p['cipher_hash'],status=r['status'],valid=self.verify(i))
            if user==p['owner']:row.update(encrypted=p['cipher'],signature=p['cipher_signature'])
            rows.append(row)
        return rows
    def search(self,user,query):
        self.authorize(user,{'owner','reviewer','auditor'})
        if not self.index:raise ValueError('Search disabled in this combination')
        allowed={r['id'] for r in self.metadata(user)}
        return [i for i in self.index.search(query) if i in allowed]
    def decide(self,user,ident,status):
        self.authorize(user,{'reviewer'})
        if self.records[ident]['payload']['recipient']!=user:raise PermissionError('Not assigned')
        if status not in ('APPROVED','REJECTED'):raise ValueError('Invalid status')
        self.read(user,ident);self.records[ident]['status']=status;self.audit.append([status,ident,time.time()])
    def revoke(self,user,target):
        self.authorize(user,{'auditor'})
        if target not in self.users:raise ValueError('Unknown user')
        self.revoked.add(target);self.audit.append(['REVOKE',target,time.time()])
    def aggregate(self,user):
        self.authorize(user,{'reviewer'})
        if not self.he:raise ValueError('Homomorphic computation disabled')
        ids=[i for i,r in self.records.items() if r['payload']['recipient']==user and r['status']!='REJECTED' and (r['payload']['expires'] is None or r['payload']['expires']>=time.time())]
        if not ids or not all(self.verify(i) for i in ids):raise ValueError('Empty/invalid batch')
        c=self.he.combine([self.records[i]['payload']['number'] for i in ids]);return {'encrypted':c,'result':self.he.decrypt(c),'operation':'sum' if self.he.kind=='PAILLIER' else 'product'}
    def export(self,user,path):
        self.authorize(user,{'auditor'})
        Path(path).write_text(json.dumps({'config':self.config,'records':self.records,'audit':self.audit},indent=2))
        # Snapshot is evidence only, not a resumable key backup.

def demo(config=None):
    s=RecordSystem(**(config or {}));i=s.upload('alice',b'Academic record: score 85','bob','education score',15);j=s.upload('eve',b'Academic record: score 91','bob','education score',25)
    print('CONFIG:',s.config);print('Encrypted package:',s.records[i]['payload']['cipher'])
    print('Hashes/signature:',s.metadata('carol'));print('Decrypted:',s.read('bob',i).decode())
    if s.index:print('Encrypted search education:',s.search('carol','education'))
    if s.he:print('Encrypted aggregate:',s.aggregate('bob'))
    s.decide('bob',i,'APPROVED');print('Decision:',s.records[i]['status'])
    try:s.read('carol',i)
    except PermissionError:print('PASS: auditor denied plaintext')
    saved=copy.deepcopy(s.records[i]);s.records[i]['payload']['plain_hash']='00'
    print('Tamper verification:',s.verify(i));s.records[i]=saved
    s.revoke('carol','alice')
    try:s.upload('alice',b'blocked')
    except PermissionError:print('PASS: revoked upload denied')
    return s

def menu(config=None):
    s=RecordSystem(**(config or {}));print('DEMO accounts: alice/eve=owner, bob=reviewer, carol=auditor; password 123')
    print('Records and keys last for this run. Export saves evidence, not restartable keys.')
    while True:
        user=input('\nUsername (0 exits): ').strip()
        if user=='0':return
        try:s.login(user,input('Password: '))
        except PermissionError as e:print(e);continue
        while True:
            print('\n1 Upload text/file  2 List metadata  3 Decrypt  4 Search  5 Aggregate  6 Approve/reject  7 Revoke  8 Export  0 Logout')
            cmd=input('Choice: ')
            try:
                if cmd=='0':break
                elif cmd=='1':
                    text=input('Text, or @file_path: ');data=Path(text[1:].strip('"')).read_bytes() if text.startswith('@') else text.encode()
                    recipient=input('Recipient [bob]: ') or 'bob';kw=input('Search keywords: ');number=int(input('Numeric value [1]: ') or '1');ttl=input('Expiry in seconds (blank=none): ')
                    i=s.upload(user,data,recipient,kw,number,time.time()+int(ttl) if ttl else None);print('Uploaded:',i,'\n',s.records[i])
                elif cmd=='2':print(json.dumps(s.metadata(user),indent=2))
                elif cmd=='3':
                    data=s.read(user,input('Record ID: '));print('Plaintext:',data);path=input('Save decrypted bytes to path (blank=skip): ')
                    if path:Path(path).write_bytes(data)
                elif cmd=='4':print('Matching IDs:',s.search(user,input('Keyword: ')))
                elif cmd=='5':print(s.aggregate(user))
                elif cmd=='6':s.decide(user,input('Record ID: '),input('APPROVED/REJECTED: ').upper());print('Saved')
                elif cmd=='7':s.revoke(user,input('Username to revoke: '));print('Revoked')
                elif cmd=='8':s.export(user,input('Snapshot JSON path: '));print('Evidence exported')
                else:print('Invalid choice')
            except (ValueError,PermissionError,KeyError,OSError) as e:print('Rejected:',e)

def main(defaults=None):
    p=argparse.ArgumentParser(description=__doc__)
    for flag,choices,default in [('encryption',ENCRYPTIONS,'AES_CBC'),('hash_name',HASHES,'SHA256'),('signature',SIGNATURES,'RSA'),('he',HE_SCHEMES,'PAILLIER'),('search',SEARCHES,'SSE')]:p.add_argument('--'+flag.replace('_','-'),choices=choices,default=(defaults or {}).get(flag,default))
    p.add_argument('--demo',action='store_true');a=vars(p.parse_args());run_demo=a.pop('demo');(demo if run_demo else menu)(a)


CONFIG = {'encryption': 'AES_OFB', 'hash_name': 'SHA512', 'signature': 'ECDSA', 'he': 'RSA', 'search': 'SSE'}
if __name__ == "__main__": main(CONFIG)
