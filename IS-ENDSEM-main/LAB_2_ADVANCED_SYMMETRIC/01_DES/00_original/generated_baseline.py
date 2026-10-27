# GENERATED BASELINE (ADDITION):
# Derived from the official DES exercise; no source listing was supplied.

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher,modes
from cryptography.hazmat.primitives import padding
import os
def key24(k8): return k8*3
def encrypt(text,k8):
 iv=os.urandom(8); p=padding.PKCS7(64).padder(); d=p.update(text.encode())+p.finalize(); e=Cipher(TripleDES(key24(k8)),modes.CBC(iv)).encryptor(); return iv,e.update(d)+e.finalize()
def decrypt(iv,c,k8):
 d=Cipher(TripleDES(key24(k8)),modes.CBC(iv)).decryptor(); raw=d.update(c)+d.finalize(); u=padding.PKCS7(64).unpadder(); return (u.update(raw)+u.finalize()).decode()
if __name__=='__main__':
 m=input('Message: '); k=b'A1B2C3D4'; iv,c=encrypt(m,k); print('Ciphertext:',c.hex()); print('Decrypted:',decrypt(iv,c,k))
