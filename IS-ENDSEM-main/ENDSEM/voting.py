"""Endsem image solution: AES-256-CBC/RSA-4096/SHA-512/ElGamal/Paillier/SSE.

Menu and real loopback socket demo. Demo users, local TSA and trusted dealer.
This is a lab simulation: no ballot validity ZK proofs or independent machines.
"""
import argparse, copy, json, socket, struct, threading, time
from crypto_blocks import *

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
