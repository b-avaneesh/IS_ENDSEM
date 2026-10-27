"""Direct classical cipher questions: actual alphabet input, configurable keys."""
import math
def clean(s):return ''.join(c for c in s.upper() if 'A'<=c<='Z')
def affine(s,a,b,decrypt=False):
    if math.gcd(a,26)!=1:raise ValueError('a must be coprime with 26')
    return ''.join(chr((((ord(c)-65-b)*pow(a,-1,26)) if decrypt else a*(ord(c)-65)+b)%26+65) for c in clean(s))
def vigenere(s,key,decrypt=False,autokey=False):
    a=[ord(c)-65 for c in clean(s)];key=[ord(c)-65 for c in clean(key)]
    if not key:raise ValueError('Empty key')
    out=[]
    for i,x in enumerate(a):
        k=key[i%len(key)] if not autokey else (key[i] if i<len(key) else (out if decrypt else a)[i-len(key)])
        out.append((x+(-k if decrypt else k))%26)
    return ''.join(chr(v+65) for v in out)
def hill(s,key,decrypt=False):
    a,b,c,d=key;det=(a*d-b*c)%26
    if math.gcd(det,26)!=1:raise ValueError('Key determinant not invertible modulo 26')
    if decrypt:
        inv=pow(det,-1,26);a,b,c,d=d*inv,-b*inv,-c*inv,a*inv
    s=clean(s);s+='X'*(len(s)%2);out=''
    for i in range(0,len(s),2):
        x,y=ord(s[i])-65,ord(s[i+1])-65;out+=chr((a*x+b*y)%26+65)+chr((c*x+d*y)%26+65)
    return out
def playfair(s,key,decrypt=False):
    square=''.join(dict.fromkeys(clean(key).replace('J','I')+'ABCDEFGHIKLMNOPQRSTUVWXYZ'));s=clean(s).replace('J','I')
    if not decrypt:
        out='';i=0
        while i<len(s):
            x=s[i];y=s[i+1] if i+1<len(s) else x
            if x==y:y='Q' if x=='X' else 'X';i+=1
            else:i+=2
            out+=x+y
        s=out
    if len(s)%2:raise ValueError('Playfair ciphertext length must be even')
    out='';shift=-1 if decrypt else 1
    for i in range(0,len(s),2):
        r,c=divmod(square.index(s[i]),5);u,v=divmod(square.index(s[i+1]),5)
        if r==u:c=(c+shift)%5;v=(v+shift)%5
        elif c==v:r=(r+shift)%5;u=(u+shift)%5
        else:c,v=v,c
        out+=square[r*5+c]+square[u*5+v]
    return out
def demo():
    s='I am learning information security'
    for a,b in [(1,20),(15,0),(15,20)]:
        ct=affine(s,a,b);print('Affine a,b:',a,b,ct,affine(ct,a,b,True))
    for key,auto in [('dollars',False),('H',True)]:
        ct=vigenere('the house is being sold tonight',key,autokey=auto);print('Vigenere/autokey:',ct,vigenere(ct,key,True,auto))
    ct=playfair('The key is hidden under the door pad','GUIDANCE');print('Playfair:',ct,playfair(ct,'GUIDANCE',True),'(fillers retained)')
    ct=hill('We live in an insecure world',(3,3,2,7));print('Hill:',ct,hill(ct,(3,3,2,7),True))
    print('Known plaintext shift yes -> CIW: key 4,',affine('XVIEWYWI',1,4,True))
    print('Affine ab -> GL: a=5 b=6:',affine('XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS',5,6,True))
if __name__=='__main__':
    import sys
    if '--demo' in sys.argv:demo()
    else:
        while True:
            mode=input('1 Additive 2 Multiplicative 3 Affine 4 Vigenere 5 Autokey 6 Playfair 7 Hill 8 Brute-force affine 9 Manual demos 0 Exit: ')
            if mode=='0':break
            if mode=='9':demo();continue
            try:
                s=input('Text: ');dec=input('Decrypt? y/n: ').lower()=='y'
                if mode in ('1','2','3'):print(affine(s,int(input('a [1]: ') or '1'),int(input('b [0]: ') or '0'),dec))
                elif mode in ('4','5'):
                    key=input('Keyword (for numeric autokey 7 enter H): ');print(vigenere(s,key,dec,mode=='5'))
                elif mode=='6':print(playfair(s,input('Key: '),dec))
                elif mode=='7':print(hill(s,tuple(map(int,input('a b c d: ').split())),dec))
                elif mode=='8':
                    for a in range(26):
                        if math.gcd(a,26)==1:
                            for b in range(26):print(a,b,affine(s,a,b,True))
            except ValueError as e:print(e)
