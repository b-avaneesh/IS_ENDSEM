from pathlib import Path
import ast
import contextlib
import io
import json
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    module = types.ModuleType('voting_test')
    module.__file__ = str(path)
    exec(compile(path.read_text(encoding='utf-8'), str(path), 'exec'), module.__dict__)
    return module


class VotingGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generator = load(ROOT / 'generator.py')
        cls.entities = {
            'Citizen': ['cast_vote'],
            'Election Office': ['verify_ballot', 'search_ballots'],
            'Counting Board': ['aggregate_votes', 'threshold_decrypt'],
            'Observer': [],
        }

    def test_original_functions_unchanged(self):
        g = self.generator
        source, entities = g.build_source(self.entities)
        original = {n.name: n for n in ast.parse(g.TEMPLATE).body if isinstance(n, ast.FunctionDef)}
        generated = {n.name: n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
        for name in original:
            if name in ('require', 'setup', 'main', 'voter', 'election_server', 'tally_authority'):
                continue
            before = ast.get_source_segment(g.TEMPLATE, original[name])
            after = ast.get_source_segment(source, generated[name])
            if name in g.REQUIREMENTS:
                before = before.replace('require("' + g.REQUIREMENTS[name] + '")', 'require("' + name + '")', 1)
            self.assertEqual(before, after, name)
        self.assertNotIn('voter', generated)
        self.assertNotIn('election_server', generated)
        self.assertEqual(entities, self.entities)

    def test_validation(self):
        for invalid in ({}, {'x': [], 'X': []}, {'': []}, {'A': ['unknown']}):
            with self.assertRaises(ValueError):
                self.generator.validate_entities(invalid)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)/'solution'
            file = self.generator.create_solution(self.entities, directory)
            before = file.read_bytes()
            with self.assertRaises(FileExistsError):
                self.generator.create_solution(self.entities, directory)
            self.assertEqual(before, file.read_bytes())

    def test_full_voting_workflow(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()) as output:
            file = self.generator.create_solution(self.entities, Path(temp)/'solution')
            m = load(file)
            m.input = lambda prompt: '2020-01-01 00:00:00' if 'starts' in prompt else '2099-12-31 23:59:59'
            m.new_password = lambda label: 'password-' + label
            m.setup()
            self.assertEqual(set(m.read('keys','accounts.json')), set(self.entities))
            m.getpass = lambda prompt: 'wrong'
            self.assertFalse(m.login('Citizen'))
            m.getpass = lambda prompt: 'password-Citizen'
            self.assertTrue(m.login('Citizen'))
            for entity in self.entities:
                m.ROLE = entity
                for action in self.generator.ACTIONS:
                    if action not in self.entities[entity]:
                        with self.assertRaises(PermissionError):
                            m.require(action)
            m.ROLE = 'Citizen'
            answers = iter(['1','B001','1','101','1','B002','2','102','2'])
            m.input = lambda prompt: next(answers)
            m.entity_menu('Citizen')
            m.ROLE = 'Election Office'
            answers = iter(['1','B001','1','101','1','B002','1','102','2'])
            m.input = lambda prompt: next(answers)
            m.entity_menu('Election Office')
            self.assertEqual(len(list((m.BASE/'verified').glob('*.json'))),2)
            m.ROLE = 'Counting Board'
            m.getpass = lambda prompt: 'password-authority 1' if '1' in prompt else 'password-authority 2'
            answers = iter(['1','2'])
            m.input = lambda prompt: next(answers)
            m.entity_menu('Counting Board')
            results = m.read('tally','final_totals.json')['results']
            self.assertEqual(results['1'],1)
            self.assertEqual(results['2'],1)
            self.assertEqual(results['3'],0)
            self.assertEqual(results['candidate_id_sum'],3)
            self.assertIn('Hash comparison: MATCH',output.getvalue())
            self.assertIn('Signature comparison: MATCH',output.getvalue())
            self.assertIn('COUNTING BOARD',output.getvalue())
            # Login/main menus use the configured entity names after restart.
            m = load(file)
            answers = iter(['4','1','2','5'])
            m.input = lambda prompt: next(answers)
            m.getpass = lambda prompt: 'password-Observer'
            m.main()
            self.assertIsNone(m.ROLE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
