"""All Lab 7 exercises and extras. python labs/lab7.py [--demo]"""
import sys,time,argparse
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from crypto_blocks import *

def run(kind='PAILLIER',a=15,b=25):
    h=Homomorphic(kind);c1,c2=h.encrypt(a),h.encrypt(b);c=h.combine([c1,c2]);answer=h.decrypt(c)
    expected=(a+b if kind=='PAILLIER' else a*b)%h.mod
    print('Scheme:',kind,'\nInputs:',a,b,'\nCiphertexts:',c1,c2,'\nEncrypted result:',c,'\nDecrypted result:',answer,'\nExpected:',expected)
    assert answer==expected
    if kind=='PAILLIER':
        print('Encrypted scalar multiplication E(a)^3 ->',h.key.decrypt(h.key.scale(c1,3)))
        print('Encrypted subtraction E(b)/E(a) ->',h.key.decrypt(c2*pow(c1,-1,h.key.n2)%h.key.n2),'(mod n)')
        print('Average after authorized decryption:',answer/2,'; not modular division of a real number')
    return answer

def threshold_demo():
    p=ThresholdPaillier();total=p.add(p.encrypt(15),p.encrypt(25));parts={i:p.partial(total,i) for i in (1,2,3)}
    try:p.combine({1:parts[1],2:parts[2]})
    except ValueError:print('PASS: two shares insufficient for this 3-of-3 scheme')
    print('3-of-3 aggregate decryption:',p.combine(parts))
    shares=split_secret(12345);print('Separate Shamir 2-of-3 custody example:',recover_secret(shares[:2]))

def benchmark():
    for name in ('PAILLIER','RSA','ELGAMAL'):
        t=time.perf_counter();h=Homomorphic(name);setup=time.perf_counter()-t
        t=time.perf_counter();cs=[h.encrypt(i) for i in range(1,11)];enc=time.perf_counter()-t
        t=time.perf_counter();c=h.combine(cs);calc=time.perf_counter()-t
        t=time.perf_counter();answer=h.decrypt(c);dec=time.perf_counter()-t
        print(name,dict(keygen_s=setup,encrypt_10_s=enc,aggregate_s=calc,decrypt_s=dec,result=answer))

def demo():
    run();run('RSA',7,3);run('ELGAMAL',7,3);threshold_demo();benchmark()

if __name__=='__main__':
    if '--demo' in sys.argv:demo()
    else:
        while True:
            c=input('1 Paillier sum/share data  2 RSA product  3 ElGamal product  4 Threshold  5 Benchmark  0 Exit: ')
            try:
                if c=='0':break
                if c in ('1','2','3'):run({'1':'PAILLIER','2':'RSA','3':'ELGAMAL'}[c],int(input('a: ')),int(input('b: ')))
                elif c=='4':threshold_demo()
                elif c=='5':benchmark()
            except ValueError as e:print(e)
