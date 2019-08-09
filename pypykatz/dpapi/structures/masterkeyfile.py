import io
import enum

from pypykatz.dpapi.constants import *

class CredHist:
	"""
	"""
	def __init__(self):
		self.version = None
		self.guid = None
		
	@staticmethod
	def from_bytes(data):
		return CredHist.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = CredHist()
		sk.version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.guid = buff.read(16)
		return sk
		
	def __str__(self):
		t = '== CredHist ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t

class DomainKey:
	"""
	"""
	def __init__(self):
		self.version = None
		self.secret_length = None
		self.access_check_length = None
		self.guid = None
		self.secret = None
		self.access_check = None
		
	@staticmethod
	def from_bytes(data):
		return DomainKey.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = DomainKey()
		sk.version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.secret_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.access_check_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.guid = buff.read(16)
		sk.secret = buff.read(sk.secret_length)
		sk.access_check = buff.read(sk.access_check_length)
		return sk
		
	def __str__(self):
		t = '== DomainKey ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t

class MasterKey:
	"""
	Represents a key, which can be for a masterkey or backupkey
	"""
	def __init__(self):
		self.version = None
		self.salt = None
		self.iteration_count = None
		self.hash_algorithm = None
		self.crypto_algorithm = None
		self.data = None
		
	@staticmethod
	def from_bytes(data):
		return MasterKey.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = MasterKey()
		sk.version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.salt = buff.read(16)
		sk.iteration_count = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.hash_algorithm = ALGORITHMS(int.from_bytes(buff.read(4), 'little', signed = False))
		sk.crypto_algorithm = ALGORITHMS(int.from_bytes(buff.read(4), 'little', signed = False))
		sk.data = buff.read()
		return sk
		
	def decrypt(self, enc_key):
		raise NotImplementedError('e')
		
	def __str__(self):
		t = '== MasterKey ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t


class MasterKeyFile:
	"""
	A masterkeyfile is a file that can hold multiple different keys, namely the masterkey, backupkey, credential history key, domainkey. 
	Not necessarily all of them present in a file
	"""
	def __init__(self):
		self.version = None
		self.unk1 = None
		self.unk2 = None
		self.guid = None
		self.unk3 = None
		self.policy = None
		self.flags = None
		self.masterkey_length = None
		self.backupkey_length = None
		self.credhist_length = None
		self.domainkey_length = None
		
		self.masterkey = None
		self.backupkey = None
		self.credhist = None
		self.domainkey = None
	
	@staticmethod
	def from_bytes(data):
		return MasterKeyFile.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = MasterKeyFile()
		sk.version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.unk1 = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.unk2 = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.guid = buff.read(72).decode('utf-16-le')
		sk.unk3 = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.policy = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.flags = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.masterkey_length = int.from_bytes(buff.read(8), 'little', signed = False)
		sk.backupkey_length = int.from_bytes(buff.read(8), 'little', signed = False)
		sk.credhist_length = int.from_bytes(buff.read(8), 'little', signed = False)
		sk.domainkey_length = int.from_bytes(buff.read(8), 'little', signed = False)
		
		if sk.masterkey_length > 0:
			sk.masterkey = MasterKey.from_bytes(buff.read(sk.masterkey_length))
		if sk.backupkey_length > 0:
			sk.backupkey = MasterKey.from_bytes(buff.read(sk.backupkey_length))
		if sk.credhist_length > 0:	
			sk.credhist = CredHist.from_bytes(buff.read(sk.credhist_length))
		if sk.domainkey_length > 0:
			sk.domainkey = DomainKey.from_bytes(buff.read(sk.domainkey_length))
		
		
		return sk
		
	def __str__(self):
		t = '== MasterKeyFile ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		

		
if __name__ == '__main__':
	filename = 'C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-3448413973-1765323015-1500960949-1105\\4c9764dc-aa99-436c-bb30-ff39b3dd407c'
	with open(filename, 'rb') as f:
		mkf = MasterKeyFile.from_bytes(f.read())
		
	print(str(mkf))	
	
		