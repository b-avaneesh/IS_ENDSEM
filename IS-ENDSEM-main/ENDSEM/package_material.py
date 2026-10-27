"""Rebuild named presets, standalone answers, reference copies and HTML finder."""
import json,shutil
from pathlib import Path
from build_combinations import export
ROOT=Path(__file__).resolve().parent
PRESETS=[
 ('01_EDUSECURE','DES_CBC','SHA256','RSA','NONE','NONE','Student -> assigned Faculty; HoD sees hashes only.'),
 ('02_MEDISECURE','AES_CBC','SHA512','ELGAMAL','PAILLIER','SSE','Patient -> assigned Doctor; Administrator audit; sum fees.'),
 ('03_BANKVAULT','TRIPLE_DES','SHA256','RSA','PAILLIER','SSE','Customer -> Manager approval/rejection; total non-rejected amounts.'),
 ('04_EMPLOYEE_SAFE','AES_CBC','SHA256','RSA','PAILLIER','SSE','Employee -> HR; salary total; keyword audit.'),
 ('05_RESULT_SECURE','AES_CBC','SHA512','SCHNORR','PAILLIER','SSE','Student -> Faculty; controller revokes; encrypted marks sum.'),
 ('06_SUPPLY_SECURE','AES_CTR','SHA256','SCHNORR','ELGAMAL','SSE','Buyer -> Supplier; approve/reject; numeric product.'),
 ('07_CLOUD_SAFE','RSA_HYBRID','SHA256','RSA','NONE','SSE','Uploader -> Receiver; fresh AES key wrapped by RSA; keyword search.'),
 ('08_CIA_STORE','ECC_HYBRID','SHA512','ECDSA','NONE','SSE','Owner -> Authorized User; auditor; verify and revoke.'),
 ('09_PAILLIER_SEARCH','AES_CBC','SHA256','RSA','PAILLIER','PAILLIER_PRIVATE_SCAN','Encrypted records with authorized Paillier equality scan; NOT PEKS.'),
 ('10_PRODUCT_ANALYTICS','RSA_HYBRID','SHA256','ELGAMAL','RSA','NONE','Hybrid records; textbook RSA numeric product on separate field.'),
 ('11_DH_RECORDS','DIFFIE_HELLMAN_AES','SHA256','RSA','PAILLIER','SSE','DH-derived AES; signed ephemeral value in package; encrypted sum.'),
 ('12_CONTENT_EXPIRY','AES_CBC','SHA256','ELGAMAL','NONE','SSE','Content owner -> assigned user; optional expiry; revoke; search.')]

def main():
    rows=json.loads((ROOT/'COMBINATION_INDEX.json').read_text());index=[]
    for name,enc,h,sig,he,se,desc in PRESETS:
        config=dict(encryption=enc,hash_name=h,signature=sig,he=he,search=se)
        r=next(r for r in rows if all(r[k]==v for k,v in config.items()))
        p=ROOT/'scenarios'/f'{name}.py'
        p.write_text('"""'+desc+'\nInternal demo users: alice/eve owner, bob reviewer, carol auditor. Rename prompts to match your question."""\nimport sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path(__file__).resolve().parents[1]))\nfrom workbench import main\nif __name__ == "__main__":main('+repr(config)+')\n')
        export(r['id'],ROOT/'standalone'/f'{name[3:]}.py')
        index.append(f'{name}.py | {desc}\n  {config} | Combination ID {r["id"]}\n')
    (ROOT/'scenarios'/'SCENARIO_MAP.txt').write_text('\n'.join(index))
    base=(ROOT/'crypto_blocks.py').read_text()
    for source,target in [('voting.py','VOTING_ENDSEM.py'),('labs/lab7.py','LAB7_ALL.py'),('labs/lab8.py','LAB8_ALL.py'),('chain.py','ORDERED_CHAIN.py')]:
        body=(ROOT/source).read_text().replace('from crypto_blocks import *','')
        body='\n'.join(l for l in body.splitlines() if not l.startswith('sys.path.insert'))
        (ROOT/'standalone'/target).write_text(base+'\n'+body)
    # Reference material only; omit private keys, generated data and binary outputs.
    ref=ROOT/'legacy_reference';ref.mkdir(exist_ok=True)
    for folder in ROOT.parent.iterdir():
        if folder.is_dir() and (folder.name.startswith('LAB_') or folder.name in ('FINAL____','COMBINATIONS','Hardcode')):
            for src in folder.rglob('*'):
                if src.is_file() and src.suffix.lower() in ('.py','.txt','.md'):
                    dst=ref/src.relative_to(ROOT.parent);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
    (ref/'requirements.txt').write_text('cryptography>=46,<51\npycryptodome\nmatplotlib\n')
    (ref/'READ_ME_FIRST.txt').write_text('Unmodified reference copies from the midsem folder. Not all were runtime-tested.\nUse new tested blocks first; see ../SOURCE_CORRECTIONS.txt. Original private keys/data were not copied.\n')
    # Small offline browser finder, no packages or remote services.
    html='''<!doctype html><html><head><meta charset="utf-8"><title>Endsem answer finder</title><style>body{font:17px system-ui;max-width:1050px;margin:40px auto;padding:20px;background:#f4f7fa;color:#152638}select,button{padding:10px;margin:6px}table{border-collapse:collapse;width:100%;background:white}td,th{padding:12px;text-align:left;border-bottom:1px solid #ddd}code{background:#e3eaf1;padding:5px}a{color:#075bad}</style></head><body><h1>Information Security Endsem</h1><p>Choose a combination, then run it or export a single copyable answer.</p><p><a href="EXAM_GUIDE.txt">Exam guide</a> · <a href="TWO_DAY_PLAN.txt">Two-day plan</a> · <a href="SOURCE_CORRECTIONS.txt">Manual corrections</a> · <a href="scenarios/SCENARIO_MAP.txt">Scenario map</a></p><p>Start the sample: <code>python voting.py --demo</code>. On this computer use <code>.\\RUN.ps1 voting.py --demo</code>.</p><div id="filters"></div><p id="count"></p><table><thead><tr><th>ID</th><th>Configuration</th><th>Export command</th></tr></thead><tbody id="rows"></tbody></table><script>const data=__DATA__;const keys=['encryption','hash_name','signature','he','search'];for(const k of keys){const label=document.createElement('label');label.textContent=k;const sel=document.createElement('select');sel.id=k;for(const value of ['ANY',...new Set(data.map(r=>r[k]))]){const op=document.createElement('option');op.textContent=value;sel.append(op)}sel.onchange=render;label.append(sel);document.getElementById('filters').append(label)}function render(){const found=data.filter(r=>keys.every(k=>document.getElementById(k).value==='ANY'||r[k]===document.getElementById(k).value));document.getElementById('count').textContent=found.length+' matches (first 60 shown). These are configurations, not predictions of every question.';const body=document.getElementById('rows');body.replaceChildren();for(const r of found.slice(0,60)){const tr=document.createElement('tr');for(const value of [String(r.id),keys.map(k=>r[k]).join(' / '),'python build_combinations.py --export '+r.id]){const td=document.createElement('td');td.textContent=value;tr.append(td)}body.append(tr)}}render();</script></body></html>'''
    (ROOT/'ANSWER_FINDER.html').write_text(html.replace('__DATA__',json.dumps(rows)),encoding='utf-8')
    print('Prepared 12 presets, 16 standalone answers, reference copies, and offline HTML finder.')
if __name__=='__main__':main()
