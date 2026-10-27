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

"""Endsem image solution: AES-256-CBC/RSA-4096/SHA-512/ElGamal/Paillier/SSE.

Menu and real loopback socket demo. Demo users, local TSA and trusted dealer.
This is a lab simulation: no ballot validity ZK proofs or independent machines.
"""
import argparse, copy, json, socket, struct, threading, time


class Election:
    def __init__(self,duration=3600):
        self.opened=time.time();self.deadline=self.opened+duration;self.closed=False
        self.candidates=[1,2,3]
        self.box=Envelope('RSA_HYBRID',rsa_bits=4096)
        self.voters={u:Signer('ELGAMAL','SHA512') for u in ('voter1','voter2','voter3')}
        self.tsa=Signer('RSA','SHA512');self.he=ThresholdPaillier();self.index=SearchIndex('SSE')
        self.records={};self.partials={};self.total=None;self.count_totals=None
        self.accounts={**{u:('123','voter') for u in self.voters},'commission':('123','commission'),'auditor':('123','auditor'),**{f'trustee{i}':(f't{i}pass','trustee') for i in (1,2,3)}}
    def auth(self,user,password):
        if user not in self.accounts or self.accounts[user][0]!=password:raise PermissionError('Invalid login')
        return self.accounts[user][1]
    def role(self,user,allowed):
        if user not in self.accounts or self.accounts[user][1] not in allowed:raise PermissionError('Role denied')
    def prepare(self,user,candidate,constituency):
        """Client step; ballot bytes, signature, encrypted ID and encrypted one-hot counts."""
        self.role(user,{'voter'})
        if candidate not in self.candidates:raise ValueError('Invalid candidate')
        ballot=canonical({'candidate':candidate,'constituency':constituency})
        rec={'voter':user,'constituency':constituency,'ballot_hash':digest(ballot,'SHA512').hex(),'ballot_signature':self.voters[user].sign(ballot),'envelope':self.box.encrypt(ballot),'encrypted_id':self.he.encrypt(candidate),'counts':[self.he.encrypt(int(candidate==c)) for c in self.candidates]}
        # Sign the entire envelope too: otherwise an attacker could replace the HE vote.
        rec['binding_signature']=self.voters[user].sign(canonical(rec))
        token={'time':time.time(),'package_hash':digest(canonical(rec),'SHA512').hex()}
        token['signature']=self.tsa.sign(canonical(token));return {'record':rec,'timestamp':token}
    def valid(self,packet):
        try:
            rec=copy.deepcopy(packet['record']);token=copy.deepcopy(packet['timestamp']);sig=token.pop('signature')
            if not self.tsa.verify(canonical(token),sig):return False
            if not self.opened<=token['time']<=self.deadline:return False
            if token['package_hash']!=digest(canonical(rec),'SHA512').hex():return False
            sig=rec.pop('binding_signature');return self.voters[rec['voter']].verify(canonical(rec),sig)
        except (ValueError,KeyError,TypeError):return False
    def accept(self,packet):
        if self.closed or time.time()>self.deadline:raise ValueError('Voting closed')
        if not self.valid(packet):raise ValueError('Timestamp/signature invalid')
        r=packet['record'];user=r['voter']
        if user in self.records:raise ValueError('Duplicate vote')
        # Server unwraps AES key and verifies ballot hash/signature; HE entries stay encrypted.
        # The supplied sample gives server the AES decryption key, so it CAN read ballots.
        ballot=self.box.decrypt(r['envelope'])
        if digest(ballot,'SHA512').hex()!=r['ballot_hash'] or not self.voters[user].verify(ballot,r['ballot_signature']):raise ValueError('Ballot integrity failed')
        fields=json.loads(ballot)
        if fields['candidate'] not in self.candidates or fields['constituency']!=r['constituency']:raise ValueError('Ballot fields invalid')
        if len(r['counts'])!=len(self.candidates):raise ValueError('Wrong counter count')
        for c in [r['encrypted_id']]+r['counts']:
            if not isinstance(c,int) or not 0<c<self.he.n2 or math.gcd(c,self.he.n)!=1:raise ValueError('Invalid Paillier ciphertext')
        # Honest-client assumption: signatures do not prove HE values match the ballot.
        self.records[user]=copy.deepcopy(packet)
        self.index.add('constituency:'+r['constituency'],user)
        self.index.add('day:'+time.strftime('%Y-%m-%d',time.gmtime(packet['timestamp']['time'])),user)
        return {'accepted':True,'voter':user,'time':packet['timestamp']['time'],'hash':r['ballot_hash']}
    def metadata(self,user):
        self.role(user,{'voter','commission','auditor','trustee'})
        return [{'voter':u,'time':p['timestamp']['time'],'hash':p['record']['ballot_hash'],'valid':self.valid(p)} for u,p in self.records.items() if self.accounts[user][1]!='voter' or u==user]
    def search(self,user,term,start=None,end=None):
        self.role(user,{'commission','auditor'})
        ids=self.index.search(term) if term else list(self.records)
        return [u for u in ids if (start is None or self.records[u]['timestamp']['time']>=start) and (end is None or self.records[u]['timestamp']['time']<=end)]
    def close(self,user):
        self.role(user,{'commission'})
        if self.closed:raise ValueError('Already closed')
        if not self.records:raise ValueError('No votes')
        if not all(self.valid(p) for p in self.records.values()):raise ValueError('Stored packet tampered')
        self.closed=True
        rs=[p['record'] for p in self.records.values()]
        self.total=self.he.add(*(r['encrypted_id'] for r in rs))
        self.count_totals=[self.he.add(*(r['counts'][i] for r in rs)) for i in range(len(self.candidates))]
        return {'encrypted_id_sum':self.total,'encrypted_counts':self.count_totals}
    def approve(self,user):
        self.role(user,{'trustee'})
        if not self.closed:raise ValueError('Close election before partial decryption')
        i=int(user[-1]);self.partials[i]=[self.he.partial(c,i) for c in [self.total]+self.count_totals]
        return {'trustee':i,'partial_decryptions':self.partials[i]}
    def result(self,user):
        self.role(user,{'commission','auditor','trustee'})
        if set(self.partials)!={1,2,3}:raise PermissionError('Need all 3 trustee approvals')
        values=[self.he.combine({i:p[j] for i,p in self.partials.items()}) for j in range(4)]
        return {'candidate_ID_sum_not_vote_counts':values[0],'counts':dict(zip(self.candidates,values[1:]))}

def recv_exact(sock,n):
    data=b''
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part:raise ConnectionError('Connection closed mid-frame')
        data+=part
    return data
def send_json(sock,obj):
    data=canonical(obj);sock.sendall(struct.pack('!I',len(data))+data)
def recv_json(sock):
    n=struct.unpack('!I',recv_exact(sock,4))[0]
    if n>8*1024*1024:raise ValueError('Frame too large')
    return json.loads(recv_exact(sock,n))

def demo(network=False):
    e=Election();print('RSA bits:',e.box.rsa.key_size,'AES: 256-CBC; hash: SHA512; signature: ElGamal')
    for u,c in [('voter1',2),('voter2',1),('voter3',2)]:
        packet=e.prepare(u,c,'A2')
        if network:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
                def serve():
                    with listener.accept()[0] as conn:
                        conn.settimeout(15)
                        try:send_json(conn,e.accept(recv_json(conn)))
                        except Exception as err:send_json(conn,{'error':str(err)})
                t=threading.Thread(target=serve);t.start()
                with socket.create_connection(('127.0.0.1',port),timeout=15) as client:send_json(client,packet);print('Socket receipt:',recv_json(client))
                t.join(timeout=20)
                if t.is_alive():raise RuntimeError('Server did not finish')
        else:print('Receipt:',e.accept(packet))
    print('Search:',e.search('auditor','constituency:A2'));print('Audit:',e.metadata('auditor'))
    print('Encrypted aggregate:',e.close('commission'))
    try:e.result('commission')
    except PermissionError:print('PASS: no result without trustees')
    for i in (1,2,3):print('Partial:',e.approve(f'trustee{i}'))
    print('Final result:',e.result('commission'));return e

def menu():
    e=Election();print('Accounts: voter1/2/3, commission, auditor: password 123. trustee1/2/3: t1pass/t2pass/t3pass.')
    print('Local lab simulation. Voting window: 1 hour. Session state is in memory.')
    while True:
        u=input('\nUsername (0 exits): ')
        if u=='0':return
        try:e.auth(u,input('Password: '))
        except PermissionError as err:print(err);continue
        while True:
            print('1 Cast vote  2 Metadata  3 Search  4 Close/tally  5 Trustee partial  6 Results  7 Export evidence  0 Logout')
            c=input('Choice: ')
            try:
                if c=='0':break
                if c=='1':
                    packet=e.prepare(u,int(input('Candidate 1/2/3: ')),input('Constituency: '));print('Encrypted/signed packet:',packet);print('Server:',e.accept(packet))
                elif c=='2':print(e.metadata(u))
                elif c=='3':
                    term=input('constituency:A2 or day:YYYY-MM-DD (blank=all): ');start=input('Start epoch seconds (blank=none): ');end=input('End epoch seconds (blank=none): ')
                    print(e.search(u,term,float(start) if start else None,float(end) if end else None))
                elif c=='4':print(e.close(u))
                elif c=='5':print(e.approve(u))
                elif c=='6':print(e.result(u))
                elif c=='7':
                    from pathlib import Path
                    e.role(u,{'commission','auditor'});Path(input('JSON path: ')).write_text(json.dumps(e.records,indent=2));print('Evidence saved; no private keys exported')
            except (ValueError,PermissionError,KeyError,OSError) as err:print('Rejected:',err)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--demo',action='store_true');p.add_argument('--socket-demo',action='store_true');a=p.parse_args()
    if a.demo or a.socket_demo:demo(a.socket_demo)
    else:menu()