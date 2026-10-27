# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import secrets,time
def exchange(p=7919,g=2):
 a=secrets.randbelow(p-3)+2; b=secrets.randbelow(p-3)+2; A=pow(g,a,p); B=pow(g,b,p); return A,B,pow(B,a,p),pow(A,b,p)
if __name__=='__main__':
 t=time.perf_counter_ns(); A,B,ka,kb=exchange(); print('Alice public:',A,'Bob public:',B); print('Secrets match:',ka==kb,'ns:',time.perf_counter_ns()-t)
