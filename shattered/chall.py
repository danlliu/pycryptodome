
# Inspired by https://xkcd.com/426/

import re

from Crypto.Hash import SHA256  # md5 is broken! let's use a better hash.

LAT = '42'
LON = '-83'

def geohash(date, key):
  h = SHA256.new()
  h.update(date + key)
  lat = h.hexdigest()[0:32]
  lon = h.hexdigest()[32:64]

  lat = re.sub(r'[a-f]', '', lat)
  lon = re.sub(r'[a-f]', '', lon)
  return LAT + '.' + lat, LON + '.' + lon

flag = open('.secret/flag', 'rb').read()
assert len(flag) == 10
assert flag[0:5] == b'wctf{'
assert flag[-1:] == b'}'

key = flag[5:-1]

for c in key:
  assert ord('a') <= c <= ord('z')

print(geohash(b'2022-10-23', key))
print(geohash(b'2022-10-24', key))
print(geohash(b'2022-10-25', key))
