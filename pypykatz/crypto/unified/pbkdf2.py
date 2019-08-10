
#https://codereview.stackexchange.com/questions/87538/python-pbkdf2-using-core-modules
import hmac
import struct
import hashlib

def pbkdf2(password, salt, iters, keylen, digestmod = hashlib.sha1):
	"""Run the PBKDF2 (Password-Based Key Derivation Function 2) algorithm
	and return the derived key. The arguments are:

	password (bytes or bytearray) -- the input password
	salt (bytes or bytearray) -- a cryptographic salt
	iters (int) -- number of iterations
	keylen (int) -- length of key to derive
	digestmod -- a cryptographic hash function: either a module
		supporting PEP 247, a hashlib constructor, or (in Python 3.4
		or later) the name of a hash function.

	For example:

	>>> import hashlib
	>>> from binascii import hexlify, unhexlify
	>>> password = b'Squeamish Ossifrage'
	>>> salt = unhexlify(b'1234567878563412')
	>>> hexlify(pbkdf2(password, salt, 500, 16, hashlib.sha1))
	b'9e8f1072bdf5ef042bd988c7da83e43b'

	"""
	h = hmac.new(password, digestmod=digestmod)
	def prf(data):
		hm = h.copy()
		hm.update(data)
		return bytearray(hm.digest())

	key = bytearray()
	i = 1
	while len(key) < keylen:
		T = U = prf(salt + struct.pack('>i', i))
		for _ in range(iters - 1):
			U = prf(U)
			T = bytearray(x ^ y for x, y in zip(T, U))
		key += T
		i += 1

	return key[:keylen]