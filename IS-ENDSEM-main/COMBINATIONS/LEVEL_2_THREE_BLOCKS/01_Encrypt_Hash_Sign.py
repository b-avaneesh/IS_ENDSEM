# MODIFICATION:
# Syllabus-grounded combination exercise. This is a student-friendly addition derived from the official exercise; no source listing was supplied.

import os,hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
msg=input('Message: ').encode(); key=AESGCM.generate_key(128); nonce=os.urandom(12); ct=AESGCM(key).encrypt(nonce,msg,None); digest=hashlib.sha256(ct).digest(); sk=rsa.generate_private_key(public_exponent=65537,key_size=2048); sig=sk.sign(digest,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); sk.public_key().verify(sig,digest,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); print('Encrypted, hashed, and signature verified')
