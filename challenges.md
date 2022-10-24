# Introduction to `pycryptodome`

Welcome to my `pycryptodome` tutorial! In this tutorial, we'll go through a lot of the major methods that you'll need to use for CTF problems. Typically `pycryptodome` is
used for Cryptography challenges, but sometimes cryptographic algorithms will appear in Reversing challenges :)

## Section 0: Setup

First, clone this repository onto your local computer, and change directories to it. All the challenges here will be solvable locally and do not require any server setup!

Let's go ahead and get our environment set up. Ensure that you have Python 3 installed on your computer.
(_Note the lines below starting with \$ are terminal commands; they should be run without the \$ included_)

```
Step 1: (optional) Set up a virtual environment
$ python3 -m venv env
$ source env/bin/activate

Step 2: Install pycryptodome
$ pip install pycryptodome

Step 3: Sanity check for installation
$ python3
>>> from Crypto.Util.number import *

If this step succeeds, you've successfully installed pycryptodome!
```

## Section 1: `Crypto.Utils`

### Numbers and strings

Let's start with the most straightforward and simple operations. First, we have the `bytes_to_long` and `long_to_bytes`. We'll see these functions pretty often especially
in RSA-based challenges.
These functions convert between string and integer representations. For example, let's consider the string `'wctf'`.

_Note: Python will be formatted how the terminal `python3` output would appear; lines starting with `>>>` are executed, while lines without `>>>` are output_

```python
>>> from Crypto.Util.number import bytes_to_long, long_to_bytes

>>> s = b'wctf'
>>> i = bytes_to_long(s)

>>> print(s)
b'wctf'
>>> print(f'{i:x}')  # print i as hex
77637466
```

If we look at the ASCII representation of these characters, we see that the raw bytes of `'wctf'` are:

```
 (w)  (c)  (t)  (f)
0x77 0x63 0x74 0x66
```

Notice how the bytes are placed in _big endian_ order, with the most significant bytes in the integer representation being placed at the left of the string representation.
By default, `pycryptodome` uses big endian.

### strxor

Next, we have `strxor`, which performs an XOR operation on individuals characters of each string. We'll see this used pretty often when challenges create their own encryption
schemes. Let's take a look at the example below:

```python
from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor

def encrypt(pt, iv, key):
    # split pt into blocks of 8 characters
    blocks = [pt[i:i+8] for i in range(0, len(pt), 8)]
    ct = ''

    for block in blocks:
        block_key = long_to_bytes(iv)
        ct_block = strxor(block, block_key)
        ct += ct_block
        iv += key
        iv %= (1 << 64)
    return ct
```

If we look through this algorithm, we see that it takes in two values, `iv` and `key`, and uses these to create a stream cipher where the key for each block is the values of
an arithmetic sequence (e.g. if `iv = 0` and `key = 2`, the block keys are `0, 2, 4, 6, ...`). Inside the loop, we take the XOR of each plaintext block with the key, and
append that to the full ciphertext string. To design the decryption function, we can replicate the key generation process to decrypt each block (XOR is its own inverse)

```python
def decrypt(pt, iv, key):
    # split ct into blocks of 8 characters
    blocks = [pt[i:i+8] for i in range(0, len(pt), 8)]
    pt = ''

    for block in blocks:
        block_key = long_to_bytes(iv)
        pt_block = strxor(block, block_key)
        pt += pt_block
        iv += key
        iv %= (1 << 64)
    return pt
```

Now that we have these functions, let's try them out on a challenge! Head over to the [numbers](numbers/challenge.md) challenge to get started!

## Section 2: `Crypto.Hash`

Next, let's take a look at the `Crypto.Hash` library. This library provides supports for hash functions.

### What are hash functions?

(If you're already familiar with the concept of hash functions, feel free to skip this section)

At the highest level, hash functions are hard-to-reverse functions that map arbitrary inputs to a seemingly random output. For example, the MD5 hash output of the string
`'wctf'` is `d0154d5048b5a5eb10ef1646400719f1`, while the hash output of the string `'xctf'` is `faba838f8bb28e75ff65f34d4f9430d7`. However, unlike real random output,
every single time a hash function is run with a specific input, it will give the same output. This makes hash functions very useful for applications such as password
verification, where a server can store the hash of the password instead of the plaintext password.

When analyzing hash functions, we look for three properties:
- Collision resistance: it is hard to find two inputs `a` and `b` such that `a` and `b` hash to the same value.
- Preimage resistance: given a hash value `h`, it is hard to find a value `a` such that `a` hashes to `h`.
- Second preimage resistance: given an input `a`, it is hard to find a value `b` such that `a` and `b` hash to the same value.

### Common hash functions

The two most common hash functions that appear in CTF challenges are MD5 and SHA-256:

- MD5 (`Crypto.Hash.MD5`): MD5 is a widely used hash function, although collisions can be generated in seconds and a preimage attack exists (although is very expensive)
- SHA-256 (`Crypto.Hash.SHA256`): SHA-256 is part of the SHA-2 group of hash functions. Unlike MD5, SHA-256 currently has no known collisions or preimage attacks.

### Computing hashes

Let's utilize MD5 as the hash function of choice for this example (the process for SHA-256 is very similar). To compute hashes, we have to create a new hash object:

```python
>>> from Crypto.Hash import MD5
>>> h = MD5.new()
```

Next, we give `h` the message we want to hash, for example `'wctf'`:

```python
>>> h.update(b'wctf')
```

Finally, we can get the _digest_ of the hash function, which is the output.

```python
>>> print(h.digest())
b'\xd0\x15MPH\xb5\xa5\xeb\x10\xef\x16F@\x07\x19\xf1'
>>> print(h.digest().hex())
'd0154d5048b5a5eb10ef1646400719f1'
```

To generate a new hash, make sure to create a new instance:

```python
>>> h = MD5.new()
>>> h.update(b'wctf')
>>> print(h.digest().hex())
'd0154d5048b5a5eb10ef1646400719f1'
>>> h.update(b'is awesome')
>>> print(h.digest().hex())
'e8c3b06c0be9ae5506cba4e5f96d9661'

>>> h = MD5.new()
>>> h.update(b'is awesome')
>>> print(h.digest().hex())
'd32bda93738f7e03adb22e66c90fbc04'
```

In this case, `'d32bda93738f7e03adb22e66c90fbc04'` is the correct hash of `'is awesome'`.

One thing with hash functions is that they are typically very computationally expensive to reverse. In some cases, CTF challenges will give you a hash to solve with "brute force". Let's take a look at one right now; head over to [shattered](shattered/challenge.md)

## Section 3: `Crypto.Cipher`

Next, we have _cipher_ algorithms. Unlike hashing algorithms, ciphers are reversible: given a _ciphertext_ that has been encrypted using a cipher, it is possible to reverse that ciphertext to _plaintext_ given knowledge of a secret _key_.

There are two general types of ciphers: _symmetric_ ciphers and _asymmetric_ ciphers. In a symmetric cipher, a user can both encrypt and decrypt messages with the same key; in an asymmetric cipher, separate keys exist for encryption and decryption. For example, AES is a symmetric cipher, where a single key is used to encrypt and decrypt. On the other hand, RSA is an asymmetric cipher, where separate encryption (public) and decryption (private) keys are used.

In this tutorial, we'll mostly focus on symmetric ciphers. One common use case for symmetric ciphers is as a _block cipher_. Block ciphers allow a single symmetric cipher and key to encrypt a message of arbitrary length. The main cipher we will use is AES, or the Advanced Encryption Standard.

### Modes of Operation

AES block ciphers can operate in a variety of modes. Let's take a look at some of the most common:

- ECB (Electronic Code Book; `AES.MODE_ECB`)
  
  In ECB mode, the AES cipher is simply applied to each block with the given key, without any modifications. ECB is the simplest out of the block cipher modes. One drawback of ECB is that the same plaintext block will always encrypt to the same ciphertext block. Thus, for files with lots of repeated contents, it becomes much easier to cryptanalyze.

- CBC (Cipher Block Chaining; `AES.MODE_CBC`)

  In CBC mode, the encrypted block is XORed with the plaintext of the next block before the next block is encrypted. CBC helps avoid the issue of having the same plaintext blocks mapping to the same ciphertext blocks through this XOR process.

- CTR (Counter; `AES.MODE_CTR`)

  CTR mode turns AES into a _stream cipher_, where a key is used to generate a sequence (or stream) that is used to encrypt the message (typically through XOR). This stream can be extended out to any length. In CTR mode, we utilize a _nonce_ value, which is concatenated with the block index (as a bytestring). This combined string is then encrypted using AES with the given key to give a part of the stream. To generate additional blocks, the block index is simply updated and the encrypted value re-computed.

### Running AES

Let's take a simple example: encrypting the message `'hello this world'` with the key `'top secret key!!'`. Notice that both of these strings are length 16 bytes; AES requires the key to be exactly 16 bytes and plaintexts to be multiples of 16 bytes. Plaintexts that do not meet this length requirement are _padded_ with additional bytes to the next multiple of 16 bytes.

```python
>>> from Crypto.Cipher import AES

>>> pt = b'hello this world'
>>> key = b'top secret key!!'

# Create a new AES instance
>>> enc = AES.new(key, AES.MODE_ECB)

# Encrypt the message
>>> ct = enc.encrypt(pt)
>>> ct.hex()
'419ea42f179d26acd395d7db92c161df'
```

Here, we see ECB mode being used for the cipher. If we encrypt the same plaintext block twice in the same message, we expect to see the same two ciphertext blocks:

```python
>>> ct2 = enc.encrypt(pt + pt)
>>> ct2.hex()[0:32]
'419ea42f179d26acd395d7db92c161df'
>>> ct2.hex()[32:64]
'419ea42f179d26acd395d7db92c161df'
```

Next, we can try encrypting with CBC mode. In this case, we will also have to provide an initialization value. Let's use `'myinitialization'` as the initialization value (also 16 bytes).

```python
>>> enc = AES.new(key, AES.MODE_CBC, iv=b'myinitialization')
>>> ct3 = enc.encrypt(pt + pt)
>>> ct3.hex()[0:32]
'2eed234bc4f9fd40c394c74953210de8'
>>> ct3.hex()[32:64]
'cbebef1a4deb487bd3c2b2621596488a'
```

Since the ciphertext of one block is used as the "initialization value" of the next, we can also use the first block as the initialization value to encrypt the second block:

```python
>>> enc = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex('2eed234bc4f9fd40c394c74953210de8'))
>>> enc.encrypt(pt).hex()
'cbebef1a4deb487bd3c2b2621596488a'
```

Finally, we can try CTR mode. In this case, we will have to provide a nonce value. Let's use `'my_nonce'` as the nonce (note that here, the nonce should be **8** bytes, since it is concatenated with an 8 byte representation of the block index)


```python
>>> enc = AES.new(key, AES.MODE_CTR, nonce=b'my_nonce')
>>> ct4 = enc.encrypt(pt + pt)
>>> ct3.hex()[0:32]
'6698aefd51cbb31a2d9b689551e4466d'
>>> ct3.hex()[32:64]
'106797e430f3b70af8acbe3e05eafc77'
```

Remember that in CTR mode, the key and nonce determine the contents of the stream. Thus, if we re-use the same instance (with the same key and nonce), we will have the same stream values!

```python
>>> from Crypto.Util.strxor import strxor
>>> enc = AES.new(key, AES.MODE_CTR, nonce=b'my_nonce')
>>> ctrkey = strxor(pt + pt, enc.encrypt(pt + pt))
>>> ctrkey.hex()
'0efdc2913eebc77244e848e23e962a098449e9515ae0d086b04b3169d45c3c5d'

# Let's say we want to encrypt the new message 'please just stop reusing the key'

>>> pt2 = b'please just stop reusing the key'

# We can predict what the encrypted output will be, given that we use the same key and nonce!

>>> strxor(ctrkey, pt2)
'7e91a7f04d8ee718319b3cc24de24579a43b8c242989bee1903f590cf4375924'

# Now to check...

>>> enc = AES.new(key, AES.MODE_CTR, nonce=b'my_nonce')
>>> enc.encrypt(pt2).hex()
'7e91a7f04d8ee718319b3cc24de24579a43b8c242989bee1903f590cf4375924'
```

For decryption, all that needs to be done is replace `encrypt` with `decrypt`!

Now that we've covered AES, check out [advanced onion standard](advancedonionstandard/challenge.md)

## Section 4: RSA

Before ending this tutorial, I'll go over a few of the various functions used by RSA challenges. Let's take a look at a relatively standard RSA implementation:

```python
from Crypto.Util.number import *

bits = 2048
p = getPrime(bits)
q = getPrime(bits)
n = p * q

e = 65537
d = inverse(e, (p - 1) * (q - 1))

def encrypt(message):
    m = bytes_to_long(message)
    enc = pow(m, e, n)
    return long_to_bytes(enc)

def decrypt(ciphertext):
    ct = bytes_to_long(message)
    dec = pow(ct, d, n)
    return long_to_bytes(dec)
```

In the code above, you can recall `bytes_to_long` and `long_to_bytes` from Section 1. The new functions are:

```
getPrime(bits): generates a random prime number with the given number of bits.
inverse(e, n): takes the inverse of `e` modulo `n`.
```

Having a general knowledge of `pycryptodome` helps when quickly analyzing RSA-based challenges; in my experience, it's one of the most popular libraries in RSA challenges for the ability to quickly generate primes and convert between strings and integers.

## Section 5: The End

This marks the end of the tutorial! I hope you've learned something new about `pycryptodome`!
