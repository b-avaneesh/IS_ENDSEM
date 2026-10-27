from pathlib import Path
import importlib.util
import json
import tempfile
import contextlib
import io
import ast
import subprocess
import sys

root = Path(r'D:\IS-ENDSEM\LAB_ENDSEM_SAMPLE_QUESTIONS\WITHOUT_SOCKET_FILE_BASED_LAB_ENDSEM_SAMPLE_PAPER_SOLUTIONS')

def load(file, base):
    spec = importlib.util.spec_from_file_location('solution_test', file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.BASE = base
    key, module.SEARCH_KEY = module.initialize()
    return module, key

passed = []
for folder in sorted(root.glob('COMBO_*')):
    file = folder / 'solution.py'
    source = file.read_text(encoding='utf-8')
    assert 'socket' not in source and 'owner_scan' not in source
    compile(source, str(file), 'exec')
    with tempfile.TemporaryDirectory(dir=r'D:\IS-ENDSEM\tmp') as temp:
        base = Path(temp)
        with contextlib.redirect_stdout(io.StringIO()):
            m, key = load(file, base)
            m.student('first.txt', 'fever fever treatment', 7, 3, key, None)
            m.student('second.txt', 'followup treatment', 5, 2, key, None)
            assert m.faculty('first.txt') == 'fever fever treatment'
            assert m.faculty('second.txt') == 'followup treatment'
            assert m.hod('first.txt') is True
            docs = m.load_documents()
            idx = m.create_index(docs, key)
            assert len(m.search(idx, 'FEVER', key, docs)) == 1
            assert len(m.search(idx, 'treatment', key, docs)) == 2
            assert not m.search(idx, 'absent', key, docs)
            assert 'fever' not in (base/'index.json').read_text()
            # Reload the module to exercise persisted asymmetric and SSE keys.
            m, key = load(file, base)
            assert m.faculty('first.txt') == 'fever fever treatment'
            assert len(m.search(json.loads((base/'index.json').read_text()), 'fever', key)) == 1
            demo = m.classical_demo('HELLO WORLD')
            assert demo['ciphertext'] and demo['decrypted_text']
            for a,b in [(7,3),(140,2)]:
                h = m.calculate_homomorphic(a,b)
                assert m.decrypt_homomorphic(h['ciphertext']) == m.expected_homomorphic(a,b)
            try:
                m.student('first.txt', 'duplicate', 7,3,key,None)
                raise AssertionError('Duplicate accepted')
            except ValueError:
                pass
            try:
                m.record_path('encrypted', '../escape')
                raise AssertionError('Traversal accepted')
            except ValueError:
                pass
            encrypted = base/'encrypted'/'first.txt'
            original = encrypted.read_text()
            encrypted.write_text('00' + original[2:])
            assert m.hod('first.txt') is False
            try:
                m.read_document('first.txt')
                raise AssertionError('Tampering accepted')
            except ValueError:
                pass
            encrypted.write_text(original)
            sigfile = base/'signature'/'first.txt'
            sig = json.loads(sigfile.read_text())
            if isinstance(sig, str):
                sig = ('00' if sig[:2] != '00' else 'ff') + sig[2:]
            else:
                sig[0] += 1
            sigfile.write_text(json.dumps(sig))
            assert not m.hod('first.txt')
        passed.append(folder.name)
        print('PASS', folder.name, flush=True)
assert len(passed) == 36
(root/'VERIFICATION.txt').write_text('All 36 solutions passed automated checks.\n\nChecked: syntax; two-document upload/decryption; independent number verification;\nHoD verification; SSE match, case handling, missing word and deduplication;\nmodule restart with persisted keys and index; classical demonstration;\nhomomorphic modular arithmetic; duplicate and path rejection;\nciphertext tampering and signature tampering rejection.\n\n'+'\n'.join(passed)+'\n')
