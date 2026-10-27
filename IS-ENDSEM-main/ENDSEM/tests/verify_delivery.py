"""Run delivered entrypoints, standalone exports and separate-process sockets."""
import ast,json,os,socket,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'tests'/'sample_outputs';OUT.mkdir(exist_ok=True)
def run(path,args=('--demo',),input=None,cwd=None):
    result=subprocess.run([sys.executable,str(ROOT/path),*args],input=input,text=True,capture_output=True,cwd=cwd or ROOT,timeout=150)
    (OUT/(Path(path).stem+'.txt')).write_text(result.stdout+result.stderr,encoding='utf-8')
    if result.returncode:raise AssertionError(f'{path}: {result.stderr}')
    print('PASS',path,flush=True);return result.stdout

for p in ROOT.rglob('*.py'):
    if 'legacy_reference' not in p.parts:ast.parse(p.read_text(encoding='utf-8-sig'))
print('All new Python files parse',flush=True)
for p in sorted((ROOT/'scenarios').glob('*.py')):run(p.relative_to(ROOT))
for p in ('labs/lab1.py','labs/lab2_6.py','labs/lab7.py','labs/lab8.py','labs/key_management.py'):run(p)
run('voting.py',('--socket-demo',))
run('chain.py',('--chain','VIGENERE','AES_CBC','RSA_HYBRID','--text','a binary chain test'))
run('combinations/AES_CBC/SHA512/ELGAMAL__PAILLIER__SSE.py')
with tempfile.TemporaryDirectory(prefix='endsem_check_') as tmp:
    for p in ('standalone/EDUSECURE.py','standalone/VOTING_ENDSEM.py','standalone/LAB7_ALL.py','standalone/LAB8_ALL.py'):run(p,cwd=tmp)
# Exercise actual menu inputs: owner upload, reviewer decrypt, auditor deny.
text='alice\n123\n1\nexam record\nbob\neducation\n15\n\n0\nbob\n123\n3\n1\n\n0\ncarol\n123\n3\n1\n0\n0\n'
out=run('scenarios/01_EDUSECURE.py',(),input=text)
assert 'Plaintext:' in out and 'Access denied' in out
for tamper in (False,True):
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    server=subprocess.Popen([sys.executable,str(ROOT/'labs/hash_socket.py'),'server','--port',str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        line=server.stdout.readline();assert 'Listening' in line
        client=subprocess.run([sys.executable,str(ROOT/'labs/hash_socket.py'),'client','--port',str(port),*(['--tamper'] if tamper else [])],capture_output=True,text=True,timeout=15)
        rest,err=server.communicate(timeout=15);assert server.returncode==client.returncode==0,(err,client.stderr)
        assert str(not tamper) in client.stdout
        (OUT/f'hash_socket_tamper_{tamper}.txt').write_text(line+rest+client.stdout)
        print('PASS separate-process hash socket; tamper=',tamper,flush=True)
    finally:
        if server.poll() is None:server.kill();server.communicate()
print('DELIVERY CHECKS PASSED',flush=True)
