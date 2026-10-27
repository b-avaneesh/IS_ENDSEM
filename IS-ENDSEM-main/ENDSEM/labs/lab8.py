"""Lab 8: ten documents, encrypted documents/index, search, private Paillier scan.

Paillier mode follows the exercise's encryption requirement with private-side
comparison; it is NOT public-server PEKS. See SOURCE_CORRECTIONS.txt.
"""
import sys,re,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from crypto_blocks import *

DOCUMENTS={str(i):text for i,text in enumerate([
    'education security student marks','hospital patient privacy health',
    'bank finance encrypted payment','voting election candidate security',
    'student scholarship education university','hospital encrypted patient report',
    'cloud file storage security','finance salary employee payroll',
    'election voting constituency audit','university library searchable document'],1)}

def build(kind):
    index=SearchIndex(kind);box=Envelope('AES_CBC');encrypted={i:box.encrypt(t.encode()) for i,t in DOCUMENTS.items()}
    for i,text in DOCUMENTS.items():
        for word in set(re.findall(r'[a-z0-9]+',text.lower())):index.add(word,i)
    return index,box,encrypted

def demo(kind='SSE'):
    start=time.perf_counter();index,box,documents=build(kind)
    print('Scheme:',kind,'Documents:',len(documents),'Build seconds:',time.perf_counter()-start)
    print('Encrypted document 1:',documents['1']);print('One encrypted index entry:',next(iter(index.entries.items())))
    for word in ('SECURITY','patient','missing'):
        t=time.perf_counter();ids=index.search(word);print('Query:',word,'IDs:',ids,'Search seconds:',time.perf_counter()-t)
        for i in ids:print(i,box.decrypt(documents[i]).decode())
    return index,box,documents

if __name__=='__main__':
    if '--demo' in sys.argv:demo();demo('PAILLIER_PRIVATE_SCAN')
    else:
        kind='PAILLIER_PRIVATE_SCAN' if input('1 SSE / 2 Paillier private-side search: ')=='2' else 'SSE'
        index,box,documents=build(kind)
        while True:
            query=input('One keyword (0 exits): ')
            if query=='0':break
            for i in index.search(query):print(i,box.decrypt(documents[i]).decode())
