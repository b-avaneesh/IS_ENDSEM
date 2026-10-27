from pathlib import Path
import ast
import json
import re
root = Path(r'D:\IS-ENDSEM\LAB_ENDSEM_SAMPLE_QUESTIONS\WITHOUT_SOCKET_FILE_BASED_LAB_ENDSEM_SAMPLE_PAPER_SOLUTIONS')
combos = json.loads((root/'COMBINATIONS_INDEX_SSE.json').read_text())
separator = r'# =========================================================\n# ([^\n]+)\n# =========================================================\n'
data = {k:{} for k in ('classical','symmetric','asymmetric','hash','signature','homomorphic')}
for c in combos:
    src = (root/c['folder']/'solution.py').read_text(encoding='utf-8')
    split = re.split(separator, src)
    sections = dict(zip(split[1::2], split[2::2]))
    funcs = {n.name:ast.get_source_segment(src,n) for n in ast.parse(src).body if isinstance(n,ast.FunctionDef)}
    constants = {}
    for n in ast.parse(split[0]).body:
        if isinstance(n,ast.Assign):
            names = {x.id for t in n.targets for x in ast.walk(t) if isinstance(x,ast.Name)}
            for key in ('BLOCK_CIPHER','SIG_P','P'):
                if key in names:
                    constants[key] = ast.get_source_segment(src,n)
    data['classical'][c['classical']] = sections[c['classical'].upper()+' CLASSICAL CIPHER'].strip()
    data['symmetric'][c['symmetric']] = constants['BLOCK_CIPHER']
    data['asymmetric'][c['asymmetric']] = {'constants':constants.get('P',''), 'code':sections[c['asymmetric']+' KEY PROTECTION'].strip()}
    data['hash'][c['hash']] = funcs['digest_text']
    sig = sections['GENERATE KEYS, SIGN MESSAGE AND VERIFY SIGNATURE'].replace(funcs['digest_text'],'').strip()
    data['signature'][c['signature']] = {'constants':constants.get('SIG_P',''), 'code':sig}
    data['homomorphic'][c['homomorphic']] = sections['HOMOMORPHIC ENCRYPTION AND DECRYPTION'].strip()
common = {name:sections[name].strip() for name in ('SSE - CREATE ENCRYPTED INDEX AND SEARCH','FILE STORAGE','STUDENT','READ DOCUMENT','FACULTY','HOD','MAIN MENU','PROGRAM START')}
common['symmetric'] = sections[c['symmetric'].upper()+' ENCRYPTION AND DECRYPTION'].strip()
common['imports'] = '\n'.join(ast.get_source_segment(src,n) for n in ast.parse(src).body if isinstance(n,(ast.Import,ast.ImportFrom)))
data['hash']['SHA512'] = 'def digest_text(text):\n    return hashlib.sha512(text.encode()).hexdigest()'
header = '''"""Generate a standalone file-based crypto lab by choosing algorithm names.
Run: python generate_solution.py
Only the generated solution requires pycryptodome. This generator uses the
standard library and carries its own templates; it can be copied anywhere.
"""
from pathlib import Path
import ast
import json
import re

'''
(root/'generate_solution.py').write_text(header+'# Embedded source templates keep this generator self-contained.\nTEMPLATES = '+repr(data)+'\n\nCOMMON = '+repr(common)+'\n\n',encoding='utf-8')
print('Embedded independent algorithm templates.')
