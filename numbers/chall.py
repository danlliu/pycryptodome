
from base64 import b64encode

from Crypto.Util.strxor import strxor
from Crypto.Util.number import *

flag = open('.secret/flag', 'rb').read()
key = open('.secret/key', 'rb').read()

ct = strxor(flag, key)
ct = bytes_to_long(ct)

key = b64encode(key).decode()
print(f'{key = }')
print(f'{ct = }')
