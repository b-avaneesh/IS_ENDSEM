import unittest, tempfile, contextlib, io
from pathlib import Path
from test_domain_generator import load, ROOT

class AlgorithmTests(unittest.TestCase):
    def test_selected_algorithms(self):
        g=load(ROOT/'generator.py')
        domain={'title':'Demo','record_name':'report','fields':[{'name':'name','type':'text','search':True}], 'min_records':1}
        configurations=[('AES-128','SHA-256','RSA','RSA','SSE'),('DES','MD5','ECDH','Schnorr','PKSE'),('Triple-DES','SHA-1','RSA','ElGamal','SSE'),('AES-192','SHA-512','ECDH','RSA','PKSE')]
        for encryption,hashing,key,signature,search in configurations:
            with self.subTest(encryption=encryption), tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                algorithms=dict(encryption=encryption,hash=hashing,key=key,signature=signature,search=search)
                file=g.create_domain_solution(domain,{'Owner':list(g.DOMAIN_ACTIONS)},Path(tmp)/'out',algorithms=algorithms)
                m=load(file);m.new_password=lambda label:'password';m.setup();m.ROLE='Owner'
                self.assertEqual(m.ALGORITHMS,g.validate_algorithms(algorithms))
                m.submit_record('R1',{'name':'Alice'})
                self.assertTrue(m.verify_record('R1'))
                self.assertEqual(m.find_records('name','alice'),['R1'])
                self.assertEqual(m.find_records('name','bob'),[])
                m=load(file);m.ROLE='Owner'
                self.assertEqual(m.view_record('R1'),{'name':'Alice'})
                digest=m.hash_message('test'); private,public=m.generate_signing_keys()
                sig=m.sign_hash(digest,private,public)
                self.assertTrue(m.verify_signature(digest,sig,public))
                self.assertFalse(m.verify_signature(m.hash_message('changed'),sig,public))
                m.aggregate_records();m.getpass=lambda prompt:'password';m.threshold_decrypt()

    def test_choices(self):
        g=load(ROOT/'generator.py')
        with self.assertRaises(ValueError):g.validate_algorithms({'hash':'unknown'})
        answers=iter(['AES-192','SHA-256','ECDH','RSA','','PKSE',''])
        g.input=lambda prompt:next(answers)
        self.assertEqual(g.choose_algorithms()['search'],'PKSE')

    def test_rsa_size_validation_and_prompts(self):
        g=load(ROOT/'generator.py')
        self.assertEqual(g.validate_algorithms()['rsa_bits'], {'key':4096,'signature':2048,'search':2048})
        for bad in [1024, 2049, 8192, True, '2048', None]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                g.validate_algorithms({'rsa_bits':{'key':bad}})
        for bad in [[], None, {'typo':2048}]:
            with self.assertRaises(ValueError):g.validate_algorithms({'rsa_bits':bad})
        prompts=[]
        answers=iter(['AES-256','SHA-512','RSA','bad','1024','2048','RSA','3072','PKSE','4096'])
        def answer(prompt):
            prompts.append(prompt)
            return next(answers)
        g.input=answer
        with contextlib.redirect_stdout(io.StringIO()):selected=g.choose_algorithms()
        self.assertEqual(selected['rsa_bits'], {'key':2048,'signature':3072,'search':4096})
        answers=iter(['AES-256','SHA-512','ECDH','ElGamal','SSE'])
        prompts.clear()
        with contextlib.redirect_stdout(io.StringIO()):g.choose_algorithms()
        self.assertFalse(any('bits' in prompt for prompt in prompts))

    def test_rsa_sizes_in_generated_keys_and_restart(self):
        from Crypto.PublicKey import RSA
        import json
        g=load(ROOT/'generator.py')
        domain={'title':'Sizes','record_name':'record','fields':[{'name':'name','type':'text','search':True}]}
        algorithms={'key':'RSA','signature':'RSA','search':'PKSE', 'rsa_bits':{'key':2048,'signature':3072,'search':4096}}
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            file=g.create_domain_solution(domain,{'Owner':list(g.DOMAIN_ACTIONS)},Path(tmp)/'out',algorithms)
            m=load(file);m.new_password=lambda label:'password';m.setup();m.ROLE='Owner'
            self.assertEqual(RSA.import_key(m.read('keys','rsa_public.json')).size_in_bits(),2048)
            self.assertEqual(RSA.import_key(m.read('keys','search_public.json')).size_in_bits(),4096)
            m.submit_record('R1',{'name':'Alice'})
            self.assertEqual(RSA.import_key(m.read('public_key','R1.json')['pem']).size_in_bits(),3072)
            self.assertTrue(m.verify_record('R1'))
            self.assertEqual(m.find_records('name','Alice'),['R1'])
            before=(m.BASE/'keys'/'rsa_private.json').read_bytes()
            m=load(file);m.setup();m.ROLE='Owner'
            self.assertEqual((m.BASE/'keys'/'rsa_private.json').read_bytes(),before)
            self.assertEqual(m.view_record('R1'),{'name':'Alice'})
            self.assertEqual(json.loads((file.parent/'algorithms.json').read_text())['rsa_bits'],algorithms['rsa_bits'])
