from pathlib import Path
import tempfile
import subprocess
import sys
root = Path(r'D:\IS-ENDSEM\LAB_ENDSEM_SAMPLE_QUESTIONS\WITHOUT_SOCKET_FILE_BASED_LAB_ENDSEM_SAMPLE_PAPER_SOLUTIONS')
for folder in sorted(root.glob('COMBO_*')):
    with tempfile.TemporaryDirectory(dir=r'D:\IS-ENDSEM\tmp') as temp:
        file = Path(temp)/'solution.py'
        file.write_text((folder/'solution.py').read_text(encoding='utf-8'), encoding='utf-8')
        answers = '\n'.join(['1','1','report1.txt','fever treatment','7','3','4','HELLO','3','2','1','report1.txt','2','FEVER','3','3','report1.txt','4',''])
        run = subprocess.run([sys.executable, str(file)], input=answers, capture_output=True, text=True, timeout=30)
        assert run.returncode == 0, (folder.name, run.stderr)
        assert 'homomorphic verified' in run.stdout and 'report1.txt : fever treatment' in run.stdout
        assert 'Signature and hash verified: True' in run.stdout
        again = subprocess.run([sys.executable, str(file)], input='2\n1\nreport1.txt\n3\n4\n', capture_output=True, text=True, timeout=30)
        assert again.returncode == 0 and 'homomorphic verified' in again.stdout, (folder.name,again.stderr)
print('All 36 interactive menu workflows and fresh-process restarts passed.')
with (root/'VERIFICATION.txt').open('a') as f:
    f.write('\nAll 36 also passed scripted interactive menus and fresh-process restarts.\n')
