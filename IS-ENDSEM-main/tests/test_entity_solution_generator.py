from pathlib import Path
from datetime import datetime
import contextlib
import hashlib
import io
import itertools
import json
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'LAB_ENDSEM_SAMPLE_QUESTIONS' / 'WITHOUT_SOCKET_FILE_BASED_LAB_ENDSEM_SAMPLE_PAPER_SOLUTIONS'
GENERATOR = DIRECTORY / 'generate_solution_with_entities.py'
ORIGINAL = DIRECTORY / 'generate_solution.py'


def load(file):
    module = types.ModuleType('test_generated')
    module.__file__ = str(file)
    exec(compile(file.read_text(encoding='utf-8'), str(file), 'exec'), module.__dict__)
    return module


class EntityGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = load(GENERATOR)
        cls.original_hash = hashlib.sha256(ORIGINAL.read_bytes()).hexdigest()

    @classmethod
    def tearDownClass(cls):
        assert hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() == cls.original_hash

    def choices(self, index=0):
        return {name: choices[index % len(choices)] for name, choices in self.g.OPTIONS.items()}

    def test_configuration(self):
        self.assertNotIn('classical', self.g.OPTIONS)
        self.assertNotIn('classical', self.g.TEMPLATES)
        for bad in [{}, {'same': [], 'SAME': []}, {'': []}, {'Indexer': ['build_index']}, {'Reader': ['unknown']}]:
            with self.assertRaises(ValueError):
                self.g.validate_entities(bad)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)/'new'
            file = self.g.create_solution('Test', self.choices(), directory, {'Owner': list(self.g.ACTIONS)})
            before = file.read_bytes()
            with self.assertRaises(FileExistsError):
                self.g.create_solution('Other', self.choices(), directory, {'Owner': []})
            self.assertEqual(before, file.read_bytes())
            for file in directory.iterdir():
                if file.suffix == '.json':
                    self.assertIsNotNone(datetime.fromisoformat(json.loads(file.read_text())['created_at']).utcoffset())
                else:
                    self.assertIn('Created at' if file.name != 'solution.py' else 'Generated at',file.read_text())

    def test_algorithms_permissions_and_timestamps(self):
        combos = itertools.product(self.g.OPTIONS['asymmetric'], self.g.OPTIONS['signature'], self.g.OPTIONS['homomorphic'])
        entities = {
            'Uploader': ['encrypt','key_encrypt','homomorphic_encrypt'],
            'Signer': ['sign','hash'],
            'Auditor': ['verify_signature','verify_hash','key_decrypt','homomorphic_decrypt'],
            'Indexer': ['decrypt','build_index'],
            'Searcher': ['search','list'],
            'Blocked': [],
        }
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()) as captured:
            for i,(asymmetric,signature,homomorphic) in enumerate(combos):
                with self.subTest(asymmetric=asymmetric,signature=signature,homomorphic=homomorphic):
                    selected = self.choices(i)
                    selected.update(asymmetric=asymmetric,signature=signature,homomorphic=homomorphic)
                    file = self.g.create_solution('Custom Entities',selected,Path(temp)/str(i),entities)
                    text = file.read_text()
                    for forbidden in ('def student(', 'def faculty(', 'def hod(', 'def classical_demo(', 'import socket'):
                        self.assertNotIn(forbidden,text)
                    m = load(file)
                    m.initialize()
                    for action in self.g.ACTIONS:
                        with self.assertRaises(PermissionError):
                            m.perform('Blocked',action,'record.txt',plaintext='secret',num1=7,num2=3,query='fever')
                    self.assertFalse((file.parent/'encrypted'/'record.txt').exists())
                    m.perform('Uploader','encrypt','record.txt',plaintext='fever fever treatment')
                    self.assertFalse((file.parent/'hashes'/'record.txt').exists())
                    self.assertFalse((file.parent/'signature'/'record.txt').exists())
                    m.perform('Signer','hash','record.txt')
                    m.perform('Signer','sign','record.txt')
                    self.assertTrue(m.perform('Auditor','verify_hash','record.txt'))
                    self.assertTrue(m.perform('Auditor','verify_signature','record.txt'))
                    m.perform('Uploader','key_encrypt','record.txt')
                    self.assertTrue(m.perform('Auditor','key_decrypt','record.txt'))
                    m.perform('Uploader','homomorphic_encrypt','record.txt',num1=7,num2=3)
                    self.assertEqual(m.perform('Auditor','homomorphic_decrypt','record.txt'),10 if homomorphic=='Paillier' else 21)
                    self.assertEqual(m.perform('Indexer','decrypt','record.txt'),'fever fever treatment')
                    m.perform('Indexer','build_index')
                    self.assertEqual(m.perform('Searcher','search',query='FEVER'),['record.txt'])
                    self.assertEqual(m.perform('Searcher','search',query='missing'),[])
                    with self.assertRaises(PermissionError):
                        m.perform('Searcher','decrypt','record.txt')
                    m.perform('Uploader','encrypt','second.txt',plaintext='treatment followup')
                    with self.assertRaises(ValueError):
                        m.perform('Searcher','search',query='treatment')
                    m.perform('Indexer','build_index')
                    self.assertEqual(m.perform('Searcher','search',query='treatment'),['record.txt','second.txt'])
                    m = load(file)
                    m.initialize()
                    self.assertEqual(m.perform('Searcher','search',query='fever'),['record.txt'])
                    self.assertEqual(m.perform('Indexer','decrypt','record.txt'),'fever fever treatment')
                    for sub in ('encrypted','metadata','hashes','signature','public_key','add','verification','keys'):
                        for artifact in (file.parent/sub).iterdir():
                            data=json.loads(artifact.read_text(encoding='utf-8'))
                            for field in ('created_at','updated_at'):
                                self.assertIsNotNone(datetime.fromisoformat(data[field]).utcoffset())
                            self.assertIn('entity',data)
                            self.assertIn('timings',data)
                            self.assertIn('data',data)
                    for logfile in ('audit.jsonl','timings.jsonl'):
                        events=[json.loads(line) for line in (file.parent/logfile).read_text().splitlines()]
                        self.assertTrue(any(e['status']=='denied' for e in events))
                        for event in events:
                            self.assertGreaterEqual(event['duration_ms'],0)
                            self.assertIsNotNone(datetime.fromisoformat(event['started_at']).utcoffset())
                            self.assertIsNotNone(datetime.fromisoformat(event['finished_at']).utcoffset())
                        self.assertNotIn('fever fever treatment',(file.parent/logfile).read_text())
                    record=file.parent/'encrypted'/'record.txt'
                    data=json.loads(record.read_text())
                    data['data']=('00' if data['data'][:2]!='00' else 'ff')+data['data'][2:]
                    record.write_text(json.dumps(data))
                    self.assertFalse(m.perform('Auditor','verify_hash','record.txt'))
                    self.assertFalse(m.perform('Auditor','verify_signature','record.txt'))
            for line in captured.getvalue().splitlines():
                self.assertRegex(line,r'^\[\d{4}-\d\d-\d\dT')

    def test_automatic_workflows(self):
        entities = {
            'Writer': ['encrypt', 'hash', 'sign'],
            'Reader': ['verify_hash', 'verify_signature', 'decrypt'],
            'Selected1256': ['encrypt', 'decrypt', 'sign', 'verify_signature'],
        }
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            file = self.g.create_solution('Workflow', self.choices(), Path(temp)/'new', entities)
            m = load(file)
            m.initialize()
            result = m.run_workflow('Writer', 'one.txt', plaintext='example text')
            self.assertEqual(result['completed'], ['encrypt', 'hash', 'sign'])
            self.assertEqual(m.run_workflow('Reader', 'one.txt')['completed'],
                             ['verify_hash', 'verify_signature', 'decrypt'])
            result = m.run_workflow('Selected1256', 'two.txt', plaintext='another record')
            self.assertEqual(result['completed'], ['encrypt', 'sign', 'verify_signature', 'decrypt'])
            self.assertFalse((file.parent/'hashes'/'two.txt').exists())
            signature = (file.parent/'signature'/'one.txt').read_bytes()
            result = m.run_workflow('Writer', 'one.txt')
            self.assertEqual(result['skipped'], ['encrypt', 'hash', 'sign'])
            self.assertEqual(signature, (file.parent/'signature'/'one.txt').read_bytes())
            # Missing artifacts are reported without granting creation permissions.
            result = m.run_workflow('Reader', 'missing.txt')
            self.assertEqual(len(result['skipped']), 3)
            encrypted = file.parent/'encrypted'/'one.txt'
            data = json.loads(encrypted.read_text())
            data['data'] = ('ff' if data['data'][:2] != 'ff' else '00') + data['data'][2:]
            encrypted.write_text(json.dumps(data))
            result = m.run_workflow('Reader', 'one.txt')
            self.assertEqual(result['failed'], ['verify_hash'])
            self.assertNotIn('decrypt', result['completed'])

    def test_interactive_standalone(self):
        with tempfile.TemporaryDirectory() as temp:
            generator=Path(temp)/GENERATOR.name
            generator.write_bytes(GENERATOR.read_bytes())
            answers='\n'.join(['Demo','AES256','SHA512','ECDH','Schnorr','Paillier','PKSE','2','Owner','all','Guest','search,list','',''])
            run=subprocess.run([sys.executable,str(generator)],input=answers,text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            solution=Path(temp)/'GENERATED_ENTITY_SOLUTIONS'/'CUSTOM_Demo'/'solution.py'
            self.assertTrue(solution.exists(),run.stdout)
            # Selecting Owner runs the full workflow; selecting Guest runs search/list.
            answers='\n'.join(['1','r.txt','fever treatment','7','3','fever','2','fever','0',''])
            run=subprocess.run([sys.executable,str(solution)],input=answers,text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('Signature verified: True',run.stdout)
            self.assertIn('Matching filenames: r.txt',run.stdout)
            self.assertNotIn('Operation could not complete',run.stdout)
            # Guest workflow still searches after a fresh process starts.
            run=subprocess.run([sys.executable,str(solution)],input='2\nfever\n0\n',text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('Matching filenames: r.txt',run.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
