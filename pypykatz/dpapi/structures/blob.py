import io
import enum

from pypykatz.dpapi.constants import *


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
		sk.masterkey_version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.masterkey_guid = buff.read(16)
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
		sk.signature_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.signature = buff.read(sk.signature_length)
		return sk
		
	
		
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