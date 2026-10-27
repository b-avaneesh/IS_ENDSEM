# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import hashlib,os
def demo(message):
 signer=rsa.generate_private_key(public_exponent=65537,key_size=2048); key=AESGCM.generate_key(128); nonce=os.urandom(12); ct=AESGCM(key).encrypt(nonce,message,None); digest=hashlib.sha256(ct).digest(); sig=signer.sign(digest,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); signer.public_key().verify(sig,digest,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); return AESGCM(key).decrypt(nonce,ct,None)
if __name__=='__main__':
 m=input('Message: ').encode(); print('Recovered after confidentiality + integrity/authenticity checks:',demo(m).decode())
