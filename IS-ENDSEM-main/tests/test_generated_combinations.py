"""Functional and socket regression checks for the 36 standalone examples.

Run with the Python environment that has pycryptodome and phe installed.
Temporary audit files are isolated from the practice folders.
"""
import ast
import concurrent.futures
import copy
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'LAB_ENDSEM_SAMPLE_QUESTIONS'
ROWS = json.loads((DEST / 'COMBINATIONS_INDEX.json').read_text())


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(row):
    folder = DEST / row['folder']
    for path in folder.glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'))
    server = load(folder / 'server.py', row['folder'])
    client = load(folder / 'client.py', row['folder'] + '_client')
    with tempfile.TemporaryDirectory() as temp:
        server.AUDIT_FILE = Path(temp) / 'audit.log'

        def request(action, role='writer', username='writer', **kwargs):
            return server.handle_request(username, role, {'action': action, **kwargs})

        text = 'Fever, fever! followup cafÃ© ä½ å¥½ ' + 'long document ' * 200
        assert request('upload', report_id='R101', content=text)['status'] == 'ok'
        result = request('get', report_id='R101')
        assert result['status'] == 'ok' and result['content'] == text, result
        assert client.digest_text(text) == result['digest']
        assert result['signature_verified']
        assert request('verify', 'auditor', 'auditor', report_id='R101')['verified']
        assert request('search', query='FEVER!')['report_ids'] == ['R101']
        assert request('search', query='cafÃ©')['report_ids'] == ['R101']
        assert request('search', query='missing')['report_ids'] == []
        assert request('search', query='two words')['status'] == 'error'
        assert request('search', query='')['status'] == 'error'
        assert request('upload', report_id='R101', content='duplicate')['status'] == 'error'
        assert request('upload', report_id='', content='bad')['status'] == 'error'
        assert request('upload', report_id='x' * 65, content='bad')['status'] == 'error'
        assert request('get', report_id='missing')['status'] == 'error'
        assert request('get', 'reader', 'reader', report_id='R101')['status'] == 'error'
        assert request('upload', 'auditor', 'auditor', report_id='X', content='bad')['status'] == 'error'
        assert request('search', 'reader', 'reader', query='fever')['report_ids'] == ['R101']
        assert request('audit', 'auditor', 'auditor')['logs']

        # Ten indexed documents, mixed overlap, deduplicated words and Unicode IDs.
        for number in range(2, 11):
            assert request('upload', report_id=f'R{number:03}', content=f'fever common entry {number}')['status'] == 'ok'
        assert len(request('search', query='fever')['report_ids']) == 10
        assert request('upload', report_id='æ–‡æ¡£', content='unicode identifier')['status'] == 'ok'
        assert request('search', query='unicode')['report_ids'] == ['æ–‡æ¡£']

        # Corrupt digest, signature and ciphertext separately. Never return plaintext.
        saved = copy.deepcopy(server.REPORTS['R101'])
        server.REPORTS['R101']['digest'] = 'bad'
        assert request('get', report_id='R101')['status'] == 'error'
        assert not request('verify', 'auditor', 'auditor', report_id='R101')['verified']
        server.REPORTS['R101'] = copy.deepcopy(saved)
        sig = server.REPORTS['R101']['signature']
        server.REPORTS['R101']['signature'] = server.b64(b'bad') if isinstance(sig, str) else [sig[0], -1]
        assert request('get', report_id='R101')['status'] == 'error'
        server.REPORTS['R101'] = copy.deepcopy(saved)
        server.REPORTS['R101']['ciphertext'] = server.b64(b'bad')
        assert request('get', report_id='R101')['status'] == 'error'
        server.REPORTS['R101'] = saved
        key = bytes([0, 255]) + bytes(range(server.KEY_BYTES - 2))
        assert server.unwrap_key(server.wrap_key(key)) == key

        name = row['classical']
        sample = 'HELLOXX'
        demo = request('classical', text=sample)
        assert demo['status'] == 'ok', demo
        expected = sample
        if name == 'Playfair':
            expected = ''.join(server.playfair_prepare_digraphs(sample))
        elif name == 'Hill':
            expected = server.hill_prepare(sample)
        elif name == 'Transposition':
            expected = sample + 'X' * (-len(sample) % 5)
        assert demo['decrypted_text'] == expected, (name, demo, expected)
        assert request('classical', text='')['status'] == 'ok'
        assert request('classical', text='cafÃ©')['status'] == 'error'
        known = {'Vigenere': 'OILWH', 'Additive': 'BYFFI', 'Multiplicative': 'BIJJC',
                 'Affine': 'VCDDW', 'Autokey': 'OLPWZ', 'Hill': 'HQOVHH'}
        if name in known:
            assert request('classical', text='HELLO')['ciphertext'] == known[name], (name, request('classical', text='HELLO'))
        hom = request('homomorphic', a=7, b=3)
        assert hom['status'] == 'ok', hom
        assert hom['decrypted_result'] == hom['expected'] == (10 if row['homomorphic'] == 'Paillier' else 21)
        if row['homomorphic'] == 'Paillier':
            assert request('homomorphic', a=-5, b=3)['decrypted_result'] == -2
        else:
            assert request('homomorphic', a=-5, b=3)['status'] == 'error'

        # Real bidirectional sockets exercise the reference's framing and login loop.
        for username, password, allowed in [('writer','write123',True), ('reader','read123',False), ('writer','wrong',False)]:
            left, right = socket.socketpair()
            right.settimeout(30)
            thread = threading.Thread(target=server.client_thread, args=(left, ('test', 0)), daemon=True)
            thread.start()
            with right, right.makefile('rwb') as stream:
                client.send_json(stream, {'username':username, 'password':password})
                response = client.recv_json(stream)
                if password == 'wrong':
                    assert response['status'] == 'error'
                else:
                    assert response['status'] == 'ok'
                    client.send_json(stream, {'action':'get', 'report_id':'R101'})
                    response = client.recv_json(stream)
                    assert (response['status'] == 'ok') == allowed
                    client.send_json(stream, {'action':'quit'})
            thread.join(timeout=10)
            assert not thread.is_alive()
    return row['folder']


def live_cli(row):
    folder = DEST / row['folder']
    # Redirect only the audit destination, so no generated runtime files remain.
    with tempfile.TemporaryDirectory() as temp:
        code = ('import importlib.util; from pathlib import Path; '
                f's=importlib.util.spec_from_file_location("example", {str(folder / "server.py")!r}); '
                'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                f'm.AUDIT_FILE=Path({str(Path(temp) / "audit.log")!r}); m.main()')
        proc = subprocess.Popen([sys.executable, '-u', '-c', code], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 90
            while True:
                if proc.poll() is not None:
                    raise AssertionError(proc.stderr.read().decode())
                try:
                    with socket.create_connection(('127.0.0.1', row['port']), timeout=1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError('Server did not start')
                    time.sleep(.1)
            inputs = 'admin\nadmin123\n1\nR101\nfever report\n2\nR101\n3\nFEVER!\n6\nR101\n7\nHELLO\n8\n7\n3\n0\n'
            if row['folder'] == 'COMBO_02_University_Results':
                inputs = ('invalid\n1\n1\n\nR101\n\nfever report\n2\nR101\n3\nFEVER!\n'
                          '4\n5\n6\nR101\n7\nHELLO\n8\noops\n-1\n7\n3\n'
                          '9\n3\n2\nR101\n9\n4\n6\nR101\n9\n2\n2\nR101\n0\n')
            result = subprocess.run([sys.executable, str(folder / 'client.py')], input=inputs, text=True, capture_output=True, timeout=60)
            assert result.returncode == 0, result.stderr
            assert 'Client hash check: True' in result.stdout
            assert '"verified": true' in result.stdout
            assert '"decrypted_result":' in result.stdout
            if row['folder'] == 'COMBO_02_University_Results':
                assert result.stdout.count('"status": "error"') == 1, result.stdout
                assert 'Permission denied for this role' in result.stdout
                assert 'Username:' not in result.stdout and 'Password:' not in result.stdout
                assert '"decrypted_result": 21' in result.stdout
                assert '"ciphertext": "BYFFI"' in result.stdout
                for user in ('admin', 'writer', 'reader', 'auditor'):
                    assert 'Selected user: ' + user in result.stdout
            else:
                assert '"status": "error"' not in result.stdout, result.stdout
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            proc.stderr.close()


if __name__ == '__main__':
    assert len(ROWS) == 36
    assert len({r['port'] for r in ROWS}) == 36
    assert len({tuple(v for k, v in r.items() if k not in ('folder','port')) for r in ROWS}) == 36
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for name in pool.map(check, ROWS):
            print('PASS', name, flush=True)
    for row in (ROWS[0], ROWS[1], ROWS[-1]):
        live_cli(row)
        print('PASS live client/server', row['folder'], flush=True)
    print('All 36 combinations and three live CLI runs passed.', flush=True)
