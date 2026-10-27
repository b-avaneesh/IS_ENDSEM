# GENERATED BASELINE (ADDITION):
# Derived from the official manual exercise; no source listing was supplied.


import hashlib,random,string,time
def run(count=50,length=32,seed=7):
 r=random.Random(seed); data=[''.join(r.choices(string.ascii_letters+string.digits,k=length)) for _ in range(count)]
 for name in ('md5','sha1','sha256'):
  t=time.perf_counter_ns(); ds=[hashlib.new(name,x.encode()).hexdigest() for x in data]; elapsed=time.perf_counter_ns()-t
  collisions=len(ds)-len(set(ds)); print(name,'ns=',elapsed,'collisions=',collisions)
if __name__=='__main__': run()
