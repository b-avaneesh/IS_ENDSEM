# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import socket,json,base64,sys
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes,serialization
HOST,PORT='127.0.0.1',5001
def server():
 with socket.socket() as s:
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((HOST,PORT)); s.listen(1); c,_=s.accept()
  with c:
   obj=json.loads(c.recv(65536)); pub=serialization.load_pem_public_key(obj['public'].encode()); msg=base64.b64decode(obj['message']); sig=base64.b64decode(obj['signature'])
   try: pub.verify(sig,msg,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); answer=b'VALID'
   except Exception: answer=b'INVALID'
   c.sendall(answer)
def client(tamper=False):
 k=rsa.generate_private_key(public_exponent=65537,key_size=2048); msg=input('Message: ').encode(); sig=k.sign(msg,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); sent=msg+b'!' if tamper else msg; obj={'public':k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode(),'message':base64.b64encode(sent).decode(),'signature':base64.b64encode(sig).decode()}
 with socket.create_connection((HOST,PORT)) as s: s.sendall(json.dumps(obj).encode()); print(s.recv(20).decode())
if __name__=='__main__': server() if len(sys.argv)<2 or sys.argv[1]=='server' else client('--tamper' in sys.argv)
