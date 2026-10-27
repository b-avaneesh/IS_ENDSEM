"""Configurable menu-driven records system. Run with --help or --demo."""
import argparse, copy, json, sys, time
from pathlib import Path
from crypto_blocks import *

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
if __name__=='__main__':main()
