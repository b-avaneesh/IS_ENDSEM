"""Arbitrary ordered encryption composition: reverse the chain to decrypt.
Example: python chain.py --chain VIGENERE AES_CBC RSA --text 'hello'
For large files prefer RSA_HYBRID to per-block RSA/ElGamal/Rabin.
"""
import argparse
from crypto_blocks import *

def run(chain,data,hash_name='SHA256',signature='RSA'):
    boxes=[Envelope(k) for k in chain];original=data;layers=[]
    for box in boxes:
        obj=box.encrypt(data);data=canonical(obj);layers.append(data)
        print('Encrypted with',box.kind,':',data[:160], '... bytes=',len(data))
    signer=Signer(signature,hash_name);sig=signer.sign(data)
    print('Original hash:',digest(original,hash_name).hex(),'Final ciphertext hash:',digest(data,hash_name).hex())
    print('Signature:',sig,'Valid:',signer.verify(data,sig),'Tamper accepted:',signer.verify(data+b'x',sig))
    if not signer.verify(data,sig):raise ValueError('Signature failed')
    for box in reversed(boxes):data=box.decrypt(json.loads(data))
    assert data==original
    print('Recovered:',data);return data

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--chain',nargs='+',choices=ENCRYPTIONS,default=['VIGENERE','AES_CBC','RSA_HYBRID']);p.add_argument('--text',default='Information Security endsem');p.add_argument('--hash-name',choices=HASHES,default='SHA256');p.add_argument('--signature',choices=SIGNATURES,default='RSA');a=p.parse_args()
    run(a.chain,a.text.encode(),a.hash_name,a.signature)
