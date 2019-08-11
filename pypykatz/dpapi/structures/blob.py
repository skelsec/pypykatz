
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import enum

from hashlib import sha1
import hmac

from pypykatz.dpapi.constants import *
from pypykatz.commons.win_datatypes import GUID
from pypykatz.crypto.unified.pkcs7 import unpad


class DPAPI_BLOB:
	def __init__(self):
		self.version = None
		self.credential_guid = None
		self.masterkey_version = None
		self.masterkey_guid = None
		self.flags = None
		self.description_length = None
		self.description = None
		self.crypto_algorithm = None
		self.crypto_algorithm_length = None
		self.salt_length = None
		self.salt = None
		self.HMAC_key_length = None
		self.HMAC_key = None
		self.hash_algorithm = None
		self.HMAC = None
		self.data_length = None
		self.data  = None
		self.signature_length = None
		self.signature = None
	
	@staticmethod
	def from_bytes(data):
		return DPAPI_BLOB.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = DPAPI_BLOB()
		sk.version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.credential_guid = buff.read(16)
		signature_start_pos = buff.tell()
		sk.masterkey_version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.masterkey_guid = GUID(buff).value
		sk.flags = FLAGS(int.from_bytes(buff.read(4), 'little', signed = False))
		sk.description_length = int.from_bytes(buff.read(4), 'little', signed = False) 
		sk.description = buff.read(sk.description_length)
		sk.crypto_algorithm = ALGORITHMS(int.from_bytes(buff.read(4), 'little', signed = False))
		sk.crypto_algorithm_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.salt_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.salt = buff.read(sk.salt_length)
		sk.HMAC_key_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.HMAC_key = buff.read(sk.HMAC_key_length)
		sk.hash_algorithm = ALGORITHMS(int.from_bytes(buff.read(4), 'little', signed = False))
		sk.hash_algorithm_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.HMAC_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.HMAC = buff.read(sk.HMAC_length)
		sk.data_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.data  = buff.read(sk.data_length)
		signature_end_pos = buff.tell()
		buff.seek(signature_start_pos, 0)
		sk.to_sign = buff.read(signature_end_pos - signature_start_pos)
		sk.signature_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.signature = buff.read(sk.signature_length)
		return sk
	
	def decrypt(self, key, entropy = None):
		def fixparity(deskey):
			temp = b''
			for i in range(len(deskey)):
				t = (bin(deskey[i])[2:]).rjust(8,'0')
				if t[:7].count('1') %2 == 0:
					temp+= int(t[:7]+'1',2).to_bytes(1, 'big')
				else:
					temp+= int(t[:7]+'0',2).to_bytes(1, 'big')
			return temp
		
		key_hash = sha1(key).digest()
		session_key_ctx = hmac.new(key_hash, self.salt, ALGORITHMS_DATA[self.hash_algorithm][1])
		if entropy is not None:
			session_key_ctx.update(entropy)
		
		session_key = session_key_ctx.digest()
		
		if len(session_key) > ALGORITHMS_DATA[self.hash_algorithm][4]:
			derived_key = hmac.new(session_key,  digestmod = ALGORITHMS_DATA[self.hash_algorithm][1]).digest()
		else:
			derived_key = session_key
		
		if len(derived_key) < ALGORITHMS_DATA[self.crypto_algorithm][0]:
			# Extend the key
			derived_key += b'\x00'*ALGORITHMS_DATA[self.hash_algorithm][4]
			ipad = bytearray([ i ^ 0x36 for i in bytearray(derived_key)][:ALGORITHMS_DATA[self.hash_algorithm][4]])
			opad = bytearray([ i ^ 0x5c for i in bytearray(derived_key)][:ALGORITHMS_DATA[self.hash_algorithm][4]])
			derived_key = ALGORITHMS_DATA[self.hash_algorithm][1](ipad).digest() + \
				ALGORITHMS_DATA[self.hash_algorithm][1](opad).digest()
			derived_key = fixparity(derived_key)
		
		cipher = ALGORITHMS_DATA[self.crypto_algorithm][1](derived_key[:ALGORITHMS_DATA[self.crypto_algorithm][0]],
					mode=ALGORITHMS_DATA[self.crypto_algorithm][2], iv=b'\x00'*ALGORITHMS_DATA[self.crypto_algorithm][3])
		cleartext = unpad(cipher.decrypt(self.data), cipher.block_size)
		
		# Calculate the different HMACKeys
		hash_block_size = ALGORITHMS_DATA[self.hash_algorithm][1]().block_size
		key_hash_2 = key_hash + b"\x00"*hash_block_size
		ipad = bytearray([i ^ 0x36 for i in bytearray(key_hash_2)][:hash_block_size])
		opad = bytearray([i ^ 0x5c for i in bytearray(key_hash_2)][:hash_block_size])
		a = ALGORITHMS_DATA[self.hash_algorithm][1](ipad)
		a.update(self.HMAC)
		
		#print('key_hash_2 : %s' % key_hash_2)
		#print('ipad : %s' % ipad)
		#print('opad : %s' % opad)
		
		hmac_calculated_1 = ALGORITHMS_DATA[self.hash_algorithm][1](opad)
		hmac_calculated_1.update(a.digest())
		
		if entropy is not None:
			hmac_calculated_1.update(entropy)
		
		hmac_calculated_1.update(self.to_sign)
		
		#print('hmac_calculated_1 : %s' % hmac_calculated_1.hexdigest())
			
		hmac_calculated_3 = hmac.new(key_hash, self.HMAC, ALGORITHMS_DATA[self.hash_algorithm][1])
		if entropy is not None:
			hmac_calculated_3.update(entropy)
			
		hmac_calculated_3.update(self.to_sign)
		
		#print('hmac_calculated_3 : %s' % hmac_calculated_3.hexdigest())
			
		if hmac_calculated_1.digest() == self.signature or hmac_calculated_3.digest() == self.signature:
			return cleartext
		else:
			return None
		
	def __str__(self):
		t = '== DPAPI_BLOB ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
if __name__ == '__main__':
	data = bytes.fromhex('01000000d08c9ddf0115d1118c7a00c04fc297eb01000000dc64974c99aa6c43bb30ff39b3dd407c0000000002000000000003660000c000000010000000f1af675a51c8283cf81abb6fb600110f0000000004800000a0000000100000009bf4e56d6c32dd59bce655496a94444c1000000088438c8f61d966ac220b4ca50933c8ee14000000314eaa780e358e70c586fb47bee0e27549be480e')
	db = DPAPI_BLOB.from_bytes(data)
	print(str(db))