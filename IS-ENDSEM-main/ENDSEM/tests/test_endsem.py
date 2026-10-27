"""Meaningful positive/negative coverage; python tests/test_endsem.py"""
import ast,copy,itertools,json,sys,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from crypto_blocks import *
from workbench import RecordSystem
from voting import Election

class Tests(unittest.TestCase):
    def test_all_encryption_roundtrips(self):
        for kind in ENCRYPTIONS:
            box=Envelope(kind)
            for data in (b'',b'JXXQ repeated aa!!\x00\xff',bytes(range(32))):
                with self.subTest(kind=kind,data=data):self.assertEqual(box.decrypt(box.encrypt(data)),data)
    def test_all_signature_hash_pairs(self):
        for kind,h in itertools.product(SIGNATURES,HASHES):
            s=Signer(kind,h);sig=s.sign(b'original')
            with self.subTest(kind=kind,h=h):
                self.assertTrue(s.verify(b'original',sig));self.assertFalse(s.verify(b'tampered',sig));self.assertFalse(Signer(kind,h).verify(b'original',sig))
    def test_homomorphic(self):
        for kind in HE_SCHEMES[1:]:
            h=Homomorphic(kind);a,b=h.encrypt(15),h.encrypt(25)
            self.assertEqual(h.decrypt(h.combine([a,b])),40 if kind=='PAILLIER' else 375)
            self.assertEqual(h.decrypt(h.combine([a])),15)
            with self.assertRaises(ValueError):h.encrypt(-1)
        p=Paillier();self.assertNotEqual(p.encrypt(5),p.encrypt(5));self.assertEqual(p.decrypt(p.scale(p.encrypt(5),3)),15)
    def test_search(self):
        for kind in SEARCHES[1:]:
            s=SearchIndex(kind)
            for word,i in [('hello','1'),('HELLO','2'),('hello','1'),('world','3')]:s.add(word,i)
            self.assertEqual(sorted(s.search('HeLLo')),['1','2']);self.assertEqual(s.search('missing'),[])
    def test_threshold(self):
        p=ThresholdPaillier();cs=[p.encrypt(0),p.encrypt(15),p.encrypt(25)];c=p.add(*cs);partials={i:p.partial(c,i) for i in (1,2,3)}
        self.assertEqual(p.combine(partials),40)
        with self.assertRaises(ValueError):p.combine({1:partials[1]})
        shares=split_secret(123456789)
        for pair in itertools.combinations(shares,2):self.assertEqual(recover_secret(pair),123456789)
        with self.assertRaises(ValueError):recover_secret(shares[:1])
    def test_permissions_expiry_tampering(self):
        s=RecordSystem();i=s.upload('alice',b'one',keywords='health',number=15);s.upload('eve',b'two',keywords='health',number=25)
        self.assertEqual(s.read('bob',i),b'one');self.assertEqual(s.aggregate('bob')['result'],40)
        with self.assertRaises(PermissionError):s.read('carol',i)
        with self.assertRaises(PermissionError):s.read('eve',i)
        with self.assertRaises(PermissionError):s.aggregate('carol')
        self.assertEqual(s.search('alice','health'),['1']);self.assertEqual(len(s.search('carol','health')),2)
        for field in ('plain_hash','cipher_hash','recipient','time','number','cipher'):
            old=copy.deepcopy(s.records[i]);s.records[i]['payload'][field]='altered';self.assertFalse(s.verify(i));s.records[i]=old
        s.decide('bob','2','REJECTED');self.assertEqual(s.aggregate('bob')['result'],15)
        expired=s.upload('alice',b'old',expires=time.time()-1)
        with self.assertRaises(PermissionError):s.read('bob',expired)
        s.revoke('carol','alice')
        with self.assertRaises(PermissionError):s.read('alice',i)
        with self.assertRaises(PermissionError):s.upload('alice',b'bad')
    def test_voting(self):
        e=Election();packet=e.prepare('voter1',2,'A2')
        for section,field in [('record','encrypted_id'),('record','counts'),('timestamp','time')]:
            bad=copy.deepcopy(packet);bad[section][field]=0
            with self.assertRaises(ValueError):e.accept(bad)
        e.accept(packet)
        with self.assertRaises(ValueError):e.accept(packet)
        e.accept(e.prepare('voter2',1,'B1'));e.accept(e.prepare('voter3',2,'A2'))
        self.assertEqual(e.search('auditor','constituency:A2'),['voter1','voter3'])
        with self.assertRaises(PermissionError):e.close('voter1')
        e.close('commission')
        with self.assertRaises(PermissionError):e.result('commission')
        e.approve('trustee1');e.approve('trustee2')
        with self.assertRaises(PermissionError):e.result('commission')
        e.approve('trustee3');self.assertEqual(e.result('commission')['counts'],{1:1,2:2,3:0})
        with self.assertRaises(ValueError):e.accept(packet)
    def test_all_generated_configs(self):
        rows=json.loads((ROOT/'COMBINATION_INDEX.json').read_text());self.assertEqual(len(rows),4608)
        self.assertEqual(len({r['path'] for r in rows}),4608)
        for row in rows:
            tree=ast.parse((ROOT/row['path']).read_text());cfg=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(getattr(t,'id',None)=='CONFIG' for t in n.targets))
            self.assertEqual(cfg,{k:row[k] for k in ('encryption','hash_name','signature','he','search')})
    def test_manual_classical_and_key_lifecycle(self):
        from labs.lab1 import affine,vigenere,hill,playfair,clean
        self.assertEqual(affine('yes',1,4),'CIW')
        self.assertEqual(affine('ab',5,6),'GL')
        for f,g in [(lambda x:affine(x,15,20),lambda x:affine(x,15,20,True)),(lambda x:vigenere(x,'dollars'),lambda x:vigenere(x,'dollars',True)),(lambda x:hill(x,(3,3,2,7)),lambda x:hill(x,(3,3,2,7),True))]:self.assertEqual(g(f('HELPME')),'HELPME')
        with self.assertRaises(ValueError):hill('test',(2,2,2,2))
        from labs.key_management import KeyService
        s=KeyService('RSA_HYBRID');s.generate('hospital');s.grant('hospital','doctor');i=s.upload('hospital','doctor',b'old');s.generate('hospital');self.assertEqual(s.read('doctor',i),b'old')
        with self.assertRaises(PermissionError):s.read('stranger',i)
        s.revoke('hospital')
        with self.assertRaises(PermissionError):s.read('doctor',i)
    def test_combined_system_each_algorithm(self):
        # 24 full systems, rotating all other settings. Primitive cross-products tested above.
        for i,enc in enumerate(ENCRYPTIONS):
            cfg=dict(encryption=enc,hash_name=HASHES[i%4],signature=SIGNATURES[(i//4)%4],he=HE_SCHEMES[i%4],search=SEARCHES[i%3])
            with self.subTest(config=cfg):
                s=RecordSystem(**cfg);r=s.upload('alice',b'hello',keywords='test',number=3)
                self.assertEqual(s.read('bob',r),b'hello');self.assertTrue(s.verify(r))
                if s.index:self.assertEqual(s.search('carol','test'),[r])
                if s.he:self.assertEqual(s.aggregate('bob')['result'],3)

if __name__=='__main__':unittest.main(verbosity=2)
