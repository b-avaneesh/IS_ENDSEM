# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import time
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
def time_cipher(algorithm,block,loops=5000):
 enc=Cipher(algorithm,modes.ECB()).encryptor(); t=time.perf_counter_ns()
 for _ in range(loops): enc.update(block)
 return time.perf_counter_ns()-t
if __name__=='__main__':
 print('AES-256 ns:',time_cipher(algorithms.AES(b'K'*32),b'X'*16))
 print('Use the DES/3DES folder for the legacy comparison and repeat with identical workload.')
