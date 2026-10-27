# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import time
def measure(label,fn,loops=1000):
 t=time.perf_counter_ns()
 for _ in range(loops): fn()
 print(label,'ns:',time.perf_counter_ns()-t)
if __name__=='__main__':
 m=42; measure('RSA',lambda:pow(pow(m,17,3233),2753,3233)); p,g,x,k=467,2,127,53; y=pow(g,x,p); c1=pow(g,k,p); c2=m*pow(y,k,p)%p; measure('ElGamal',lambda:c2*pow(pow(c1,x,p),-1,p)%p); n=499*547; c=m*m%n; measure('Rabin encryption',lambda:m*m%n); print('Rabin ciphertext:',c)
