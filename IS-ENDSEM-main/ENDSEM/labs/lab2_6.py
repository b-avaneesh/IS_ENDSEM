"""Lab 2/3 encryption and timing; Lab 5 hashing; Lab 6 signatures."""
import sys,time,secrets
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from crypto_blocks import *
def custom_hash(text):
    h=5381
    for c in text:
        h=h*33+ord(c);h=(h^(h>>16))&0xffffffff
    return h
def cipher_demo(kind,data):
    start=time.perf_counter();box=Envelope(kind);setup=time.perf_counter()-start
    start=time.perf_counter();ct=box.encrypt(data);enc=time.perf_counter()-start
    start=time.perf_counter();plain=box.decrypt(ct);dec=time.perf_counter()-start
    assert plain==data
    print(kind,'Cipher:',ct,'Plain:',plain,'Keygen s:',setup,'Encryption s:',enc,'Decryption s:',dec)
def hashes_demo():
    dataset=[secrets.token_hex(32).encode() for _ in range(100)]
    for name in HASHES:
        start=time.perf_counter();values=[digest(x,name) for x in dataset];elapsed=time.perf_counter()-start
        print(name,'100 strings seconds:',elapsed,'Observed collisions:',len(values)-len(set(values)))
    print('No collision in a tiny sample is not evidence of collision resistance.')
def signature_demo(kind,text):
    s=Signer(kind,'SHA256');sig=s.sign(text);print('Signature:',sig,'Verified:',s.verify(text,sig),'Tampered:',s.verify(text+b'!',sig))
if __name__=='__main__':
    if '--demo' in sys.argv:
        for k in ENCRYPTIONS[8:]:cipher_demo(k,b'Lab message')
        hashes_demo()
        for k in SIGNATURES:signature_demo(k,b'Signed message')
    else:
        while True:
            c=input('1 Encrypt/decrypt/timing 2 Custom hash 3 Hash comparison 4 Sign/verify 0 Exit: ')
            if c=='0':break
            try:
                if c=='1':
                    print(ENCRYPTIONS);kind=input('Algorithm: ').upper();cipher_demo(kind,input('Text: ').encode())
                elif c=='2':print(custom_hash(input('Text: ')))
                elif c=='3':hashes_demo()
                elif c=='4':
                    print(SIGNATURES);signature_demo(input('Signature algorithm: ').upper(),input('Text: ').encode())
            except (ValueError,KeyError) as e:print(e)
