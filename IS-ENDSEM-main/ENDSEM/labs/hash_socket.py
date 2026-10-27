"""Run server and client in two terminals. Framed multipart integrity, Lab 5."""
import argparse,hashlib,json,socket,struct
def receive(sock,n):
    data=b''
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk:raise ConnectionError('Truncated message')
        data+=chunk
    return data
def send(sock,data):sock.sendall(struct.pack('!I',len(data))+data)
def recv(sock):
    n=struct.unpack('!I',receive(sock,4))[0]
    if n>1024*1024:raise ValueError('Message too large')
    return receive(sock,n)
def server(port):
    with socket.socket() as s:
        s.bind(('127.0.0.1',port));s.listen();print('Listening on',port,flush=True)
        with s.accept()[0] as conn:
            conn.settimeout(30);parts=json.loads(recv(conn));data=b''.join(bytes.fromhex(x) for x in parts)
            send(conn,hashlib.sha256(data).hexdigest().encode());print('Reassembled:',data)
def client(port,text,tamper=False):
    original=text.encode();parts=[original[i:i+4] for i in range(0,len(original),4)]
    if tamper:parts.append(b'!')
    with socket.create_connection(('127.0.0.1',port),timeout=10) as s:
        send(s,json.dumps([p.hex() for p in parts]).encode());remote=recv(s).decode()
    ok=remote==hashlib.sha256(original).hexdigest();print('Integrity verified:',ok);return ok
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['server','client']);p.add_argument('--port',type=int,default=5055);p.add_argument('--text',default='Information Security');p.add_argument('--tamper',action='store_true');a=p.parse_args()
    server(a.port) if a.mode=='server' else client(a.port,a.text,a.tamper)
