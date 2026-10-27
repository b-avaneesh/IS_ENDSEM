"""Build all 4,608 parameter combinations and export standalone answers."""
import argparse,itertools,json
from pathlib import Path
from crypto_blocks import ENCRYPTIONS,HASHES,SIGNATURES,HE_SCHEMES,SEARCHES
ROOT=Path(__file__).resolve().parent

def build():
    rows=[]
    full=(ROOT/'crypto_blocks.py').read_text()+'\n'+(ROOT/'workbench.py').read_text().replace('from crypto_blocks import *','').replace("if __name__=='__main__':main()",'')
    for number,(enc,h,sig,he,search) in enumerate(itertools.product(ENCRYPTIONS,HASHES,SIGNATURES,HE_SCHEMES,SEARCHES),1):
        config=dict(encryption=enc,hash_name=h,signature=sig,he=he,search=search)
        path=Path('combinations')/enc/h/f'{sig}__{he}__{search}.py'
        target=ROOT/path;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text('# Self-contained generated combination; requires cryptography only.\n'+full+'\nCONFIG = '+repr(config)+'\nif __name__ == "__main__": main(CONFIG)\n')
        rows.append(dict(id=number,path=path.as_posix(),**config))
    (ROOT/'COMBINATION_INDEX.json').write_text(json.dumps(rows,indent=2))
    (ROOT/'COMBINATION_INDEX.txt').write_text('ID | ENCRYPTION | HASH | SIGNATURE | HE | SEARCH | FILE\n'+'\n'.join(' | '.join(str(r[k]) for k in ('id','encryption','hash_name','signature','he','search','path')) for r in rows))
    print('Generated',len(rows),'self-contained programs. No claim of all possible exam questions.')

def export(ident,output=None):
    rows=json.loads((ROOT/'COMBINATION_INDEX.json').read_text());row=next(r for r in rows if r['id']==ident)
    code=(ROOT/'crypto_blocks.py').read_text()+'\n'+(ROOT/'workbench.py').read_text().replace('from crypto_blocks import *','').replace("if __name__=='__main__':main()",'')
    config={k:row[k] for k in ('encryption','hash_name','signature','he','search')}
    code+='\nif __name__ == "__main__": main('+repr(config)+')\n'
    p=Path(output) if output else ROOT/'standalone'/f'ANSWER_{ident:04d}.py';p.parent.mkdir(parents=True,exist_ok=True);p.write_text(code)
    print('Standalone answer:',p)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--export',type=int);p.add_argument('--output');a=p.parse_args()
    export(a.export,a.output) if a.export else build()
