# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
def derive(private,public): return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'lab-ecdh').derive(private.exchange(ec.ECDH(),public))
if __name__=='__main__':
 a=ec.generate_private_key(ec.SECP256R1()); b=ec.generate_private_key(ec.SECP256R1()); ka=derive(a,b.public_key()); kb=derive(b,a.public_key()); print('Derived keys match:',ka==kb); print('Key:',ka.hex())
