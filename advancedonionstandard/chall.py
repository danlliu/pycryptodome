
from Crypto.Cipher import AES
from Crypto.Util.Padding import *

def encrypt_round1(message, key):
  enc = AES.new(key, AES.MODE_ECB)
  ciphertext = enc.encrypt(message)
  return ciphertext

def encrypt_round2(message, key, iv):
  enc = AES.new(key, AES.MODE_CBC, iv=iv)
  ciphertext = enc.encrypt(message)
  return ciphertext

def encrypt_round3(message, key, nonce):
  enc = AES.new(key, AES.MODE_CTR, nonce=nonce)
  ciphertext = enc.encrypt(message)
  return ciphertext

key1 = open('.secret/key1', 'rb').read().strip()
key2 = open('.secret/key2', 'rb').read().strip()
key3 = open('.secret/key3', 'rb').read().strip()
iv = open('.secret/iv', 'rb').read().strip()
nonce = open('.secret/nonce', 'rb').read().strip()

m1 = b'unrelated message that definitely won\'t help you get the flag at all, of course it definitely wouldn\'t or else why would i give it to you? anyways see you later good luck decrypting muahahahaha'
flag = open('.secret/flag', 'rb').read()

m1 = pad(m1, 16)
flag = pad(flag, 16)

print(encrypt_round3(m1, key3, nonce).hex())

r1 = key1 + encrypt_round1(flag, key1)
r2 = key2 + iv + encrypt_round2(r1, key2, iv)
r3 = encrypt_round3(r2, key3, nonce)

print(r3.hex())
