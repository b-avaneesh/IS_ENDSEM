"""Lab 4 key lifecycle: generate, grant, expiry, revoke, versioned rotation.
Session demo. Existing ciphertext stays associated with its original key version.
"""
import sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from crypto_blocks import Envelope

class KeyService:
    def __init__(self,kind='RABIN'):
        self.kind=kind;self.versions={};self.current={};self.grants={};self.revoked=set();self.log=[];self.records={}
    def generate(self,facility,lifetime=3600):
        version=self.current.get(facility,0)+1
        self.versions[(facility,version)]=(Envelope(self.kind),time.time()+lifetime)
        self.current[facility]=version;self.revoked.discard(facility);self.log.append(('GENERATE',facility,version,time.time()));return version
    def grant(self,facility,user,seconds=3600):
        if facility not in self.current:raise KeyError('Generate facility first')
        self.grants[(facility,user)]=time.time()+seconds;self.log.append(('GRANT',facility,user,time.time()))
    def revoke(self,facility):self.revoked.add(facility);self.log.append(('REVOKE',facility,time.time()))
    def permitted(self,facility,user):
        if facility in self.revoked or time.time()>self.grants.get((facility,user),0):raise PermissionError('Revoked or expired grant')
    def upload(self,facility,user,data):
        self.permitted(facility,user);version=self.current[facility];box,expiry=self.versions[(facility,version)]
        if time.time()>expiry:raise PermissionError('Key expired; renew it')
        ident=str(len(self.records)+1);self.records[ident]=(facility,version,box.encrypt(data));self.log.append(('ENCRYPT',ident,version,time.time()));return ident
    def read(self,user,ident):
        facility,version,ct=self.records[ident];self.permitted(facility,user)
        # Rotation expiry prevents new encryption, but archived keys allow old reads.
        self.log.append(('DECRYPT',ident,user,time.time()));return self.versions[(facility,version)][0].decrypt(ct)
    def renew_due(self):
        for facility,version in list(self.current.items()):
            if facility not in self.revoked and time.time()>self.versions[(facility,version)][1]:self.generate(facility)

def demo():
    s=KeyService();s.generate('hospital');s.grant('hospital','doctor');i=s.upload('hospital','doctor',b'patient report')
    print('Before rotation:',s.read('doctor',i));s.generate('hospital');print('After rotation old record:',s.read('doctor',i))
    s.revoke('hospital')
    try:s.read('doctor',i)
    except PermissionError:print('PASS: facility revocation enforced')
    print('Audit:',s.log)

if __name__=='__main__':
    if '--demo' in sys.argv:demo()
    else:
        s=KeyService(input('RABIN / ELGAMAL / RSA_HYBRID [RABIN]: ').upper() or 'RABIN')
        print('Administrative lab console; no network API or durable private-key store.')
        while True:
            c=input('1 Generate/rotate 2 Grant 3 Upload 4 Read 5 Revoke 6 Renew expired 7 Audit 0 Exit: ')
            try:
                if c=='0':break
                elif c=='1':print(s.generate(input('Facility: '),int(input('Key lifetime seconds: '))))
                elif c=='2':s.grant(input('Facility: '),input('User: '),int(input('Grant seconds: ')))
                elif c=='3':print(s.upload(input('Facility: '),input('User: '),input('Data: ').encode()))
                elif c=='4':print(s.read(input('User: '),input('Record ID: ')))
                elif c=='5':s.revoke(input('Facility: '))
                elif c=='6':s.renew_due()
                elif c=='7':print(s.log)
            except (ValueError,KeyError,PermissionError) as e:print(e)
