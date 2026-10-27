# MODIFICATION:
# tamper detection. This is a student-friendly addition derived from the official exercise; no source listing was supplied.


from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
def sign(private,data): return private.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
def verify(public,data,sig):
 try: public.verify(sig,data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); return True
 except Exception:return False
if __name__=='__main__':
 k=rsa.generate_private_key(public_exponent=65537,key_size=2048); m=input('Message: ').encode(); s=sign(k,m); print('Signature:',s.hex()); print('Valid:',verify(k.public_key(),m,s)); print('Tampered valid:',verify(k.public_key(),m+b'!',s))
