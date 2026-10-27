# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import socket,hashlib
HOST,PORT='127.0.0.1',5000
def serve_once():
 with socket.socket() as s:
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((HOST,PORT)); s.listen(1)
  conn,_=s.accept()
  with conn:
   data=b''
   while True:
    part=conn.recv(4096)
    if not part: break
    data+=part
   conn.sendall(hashlib.sha256(data).hexdigest().encode())
if __name__=='__main__': serve_once()
