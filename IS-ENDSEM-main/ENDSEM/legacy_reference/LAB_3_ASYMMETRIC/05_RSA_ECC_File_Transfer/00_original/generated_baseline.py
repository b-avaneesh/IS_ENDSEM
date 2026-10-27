# GENERATED BASELINE (ADDITION):
# Derived from the official file-transfer exercise; no source listing was supplied.

from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os
def protect(data):
 private=rsa.generate_private_key(public_exponent=65537,key_size=2048); key=AESGCM.generate_key(128); nonce=os.urandom(12); ct=AESGCM(key).encrypt(nonce,data,None); wrapped=private.public_key().encrypt(key,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)); return private,wrapped,nonce,ct
def recover(private,wrapped,nonce,ct):
 key=private.decrypt(wrapped,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)); return AESGCM(key).decrypt(nonce,ct,None)
if __name__=='__main__':
 d=input('Data: ').encode(); bundle=protect(d); print('Recovered:',recover(*bundle).decode())
