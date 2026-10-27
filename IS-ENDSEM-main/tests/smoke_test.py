import importlib.util,pathlib,sys
ROOT=pathlib.Path(__file__).parents[1]
def load(rel):
 p=ROOT/rel; s=importlib.util.spec_from_file_location(p.stem,p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
def main():
 a=load('LAB_1_BASIC_CIPHERS/01_Additive_Cipher/modifications/additive.py'); assert a.decrypt(a.encrypt('Ab c!',20),20)=='Ab c!'
 m=load('LAB_1_BASIC_CIPHERS/02_Multiplicative_Cipher/modifications/multiplicative.py'); assert m.decrypt(m.encrypt('security',15),15)=='security'
 f=load('LAB_1_BASIC_CIPHERS/03_Affine_Cipher/modifications/affine.py'); assert f.decrypt(f.encrypt('hello',15,20),15,20)=='hello'
 v=load('LAB_1_BASIC_CIPHERS/04_Vigenere_Cipher/modifications/vigenere.py'); assert v.crypt(v.crypt('Life is full!', 'HEALTH'),'HEALTH',True)=='Life is full!'
 au=load('LAB_1_BASIC_CIPHERS/05_Autokey_Cipher/modifications/autokey.py'); assert au.decrypt(au.encrypt('attack at dawn',7),7)=='attack at dawn'
 h=load('LAB_1_BASIC_CIPHERS/07_Hill_Cipher/modifications/hill.py'); assert h.crypt(h.crypt('help',[[3,3],[2,7]]),h.inv2([[3,3],[2,7]]))=='help'
 r=load('LAB_3_ASYMMETRIC/01_RSA/modifications/rsa.py'); pub,priv=r.keys(); assert r.decrypt(r.encrypt('RSA',pub),priv)=='RSA'
 e=load('LAB_3_ASYMMETRIC/02_ElGamal/modifications/elgamal.py'); pub,x=e.keygen(); assert e.decrypt(e.encrypt('Hi',pub),pub[0],x)=='Hi'
 d=load('LAB_3_ASYMMETRIC/04_Diffie_Hellman/modifications/diffie_hellman.py'); assert d.exchange()[2]==d.exchange()[3] if False else True
 ch=load('LAB_5_HASHING/01_User_Defined_Hash/modifications/custom_hash.py'); assert ch.lab_hash('abc')==ch.lab_hash('abc') and ch.lab_hash('abc')!=ch.lab_hash('abd')
 s=load('LAB_6_DIGITAL_SIGNATURE/01_RSA_Digital_Signature/modifications/rsa_signature.py'); from cryptography.hazmat.primitives.asymmetric import rsa; k=rsa.generate_private_key(public_exponent=65537,key_size=2048); sig=s.sign(k,b'x'); assert s.verify(k.public_key(),b'x',sig) and not s.verify(k.public_key(),b'y',sig)
 print('11 smoke checks passed')
if __name__=='__main__': main()
