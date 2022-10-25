
from Crypto.Util.number import *

p = getPrime(1024)
q = getPrime(1024)

n = p * q
print(f'{n = }')

# if `e` is too small, you get small-e attacks. so let's make it really big.
d = 65537
e = inverse(d, (p-1)*(q-1))

flag = open('.secret/flag', 'rb').read()
pt = bytes_to_long(flag)

ct = pow(pt, e, n)
print(f'{ct = }')
