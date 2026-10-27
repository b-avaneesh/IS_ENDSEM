from pathlib import Path
import importlib.util
import tempfile
import contextlib
import io
import itertools
import subprocess
import sys
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT/'LAB_ENDSEM_SAMPLE_QUESTIONS'/'WITHOUT_SOCKET_FILE_BASED_LAB_ENDSEM_SAMPLE_PAPER_SOLUTIONS'/'generate_solution.py'

def load(file, name):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = load(GENERATOR, 'generator')

    def test_aliases_and_invalid_names(self):
        for category, text, expected in [('symmetric','AES256','AES-256'),('symmetric','3des','Triple-DES'),('hash','SHA-256','SHA256'),('asymmetric','diffie hellman','DH')]:
            self.assertEqual(self.g.canonical_algorithm(category,text),expected)
        for category, name in [('search','PKSE'),('hash','unknown'),('symmetric','AES512')]:
            with self.assertRaises(ValueError):
                self.g.canonical_algorithm(category,name)

    def test_independent_combinations(self):
        # Every asymmetric/signature/homomorphic cross-product, rotating every
        # classical cipher, symmetric cipher and hash independently.
        combinations = itertools.product(self.g.OPTIONS['asymmetric'],self.g.OPTIONS['signature'],self.g.OPTIONS['homomorphic'])
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            for i,(asymmetric,signature,homomorphic) in enumerate(combinations):
                with self.subTest(asymmetric=asymmetric,signature=signature,homomorphic=homomorphic):
                    choices = {k:v[i%len(v)] for k,v in self.g.OPTIONS.items()}
                    choices.update(asymmetric=asymmetric,signature=signature,homomorphic=homomorphic)
                    directory = Path(temp)/str(i)
                    file = self.g.create_solution('Custom test', choices, directory)
                    source = file.read_text()
                    self.assertNotIn('socket',source)
                    module = load(file,'generated')
                    key,module.SEARCH_KEY = module.initialize()
                    module.student('first.txt','fever fever treatment',7,3,key,None)
                    module.student('second.txt','treatment followup',5,2,key,None)
                    self.assertEqual(module.faculty('first.txt'),'fever fever treatment')
                    self.assertEqual(module.faculty('second.txt'),'treatment followup')
                    self.assertTrue(module.hod('first.txt'))
                    index = module.create_index(module.load_documents(),key)
                    self.assertEqual(len(module.search(index,'FEVER',key)),1)
                    self.assertEqual(len(module.search(index,'treatment',key)),2)
                    self.assertFalse(module.search(index,'missing',key))
                    self.assertTrue(module.classical_demo('HELLO WORLD')['ciphertext'])
                    restarted = load(file,'restarted')
                    key,restarted.SEARCH_KEY = restarted.initialize()
                    self.assertEqual(restarted.faculty('first.txt'),'fever fever treatment')
                    ciphertext = directory/'encrypted'/'first.txt'
                    original = ciphertext.read_text()
                    ciphertext.write_text(('ff' if original[:2]!='ff' else '00')+original[2:])
                    self.assertFalse(restarted.hod('first.txt'))
                    with self.assertRaises(ValueError):
                        restarted.read_document('first.txt')
                    with self.assertRaises(FileExistsError):
                        self.g.create_solution('Other',choices,directory)
                    self.assertEqual(file.read_text(),source)

    def test_generator_and_solution_interactive(self):
        with tempfile.TemporaryDirectory() as temp:
            # Copy ONLY generator: no repo/template/attachment dependencies.
            generator = Path(temp)/'generate_solution.py'
            generator.write_text(GENERATOR.read_text(encoding='utf-8'),encoding='utf-8')
            answers = '\n'.join(['My Custom Lab','affine','invalid','3des','sha512','ecdh','schnorr','paillier','','',''])
            run = subprocess.run([sys.executable,str(generator)],input=answers,text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            file = Path(temp)/'GENERATED_SOLUTIONS'/'CUSTOM_My_Custom_Lab'/'solution.py'
            self.assertTrue(file.exists(),run.stdout)
            answers = '\n'.join(['1','1','record.txt','fever treatment','7','3','3','2','1','record.txt','2','fever','3','3','record.txt','4',''])
            run = subprocess.run([sys.executable,str(file)],input=answers,text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('homomorphic verified',run.stdout)
            self.assertIn('record.txt : fever treatment',run.stdout)
            run = subprocess.run([sys.executable,str(file)],input='2\n1\nrecord.txt\n3\n4\n',text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('homomorphic verified',run.stdout)

if __name__ == '__main__':
    unittest.main(verbosity=2)
