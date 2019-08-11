#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import enum
import sys

from pypykatz.dpapi.constants import *
from hashlib import sha1
import hmac


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
		
	def decrypt(self, key):
		if self.hash_algorithm == ALGORITHMS.CALG_HMAC:
			hash_type = sha1
		else:
			hash_type = ALGORITHMS_DATA[self.hash_algorithm][1]
		
		keylen = ALGORITHMS_DATA[self.crypto_algorithm][0] + ALGORITHMS_DATA[self.crypto_algorithm][3]
		
		temp_key_blob = b""
		i = 1
		while len(temp_key_blob) < keylen:
			U = self.salt + i.to_bytes(4, 'big', signed = False)
			i += 1
			derived = hmac.new(key, U, hash_type).digest()
			for _ in range(self.iteration_count - 1):
				actual = hmac.new(key,derived, hash_type).digest()
				derived = (int.from_bytes(derived, sys.byteorder) ^ int.from_bytes(actual, sys.byteorder)).to_bytes(len(actual), sys.byteorder)
			temp_key_blob += derived

		temp_key = temp_key_blob[:keylen]
		#print('temp_key : %s' % temp_key)
		crypt_key = temp_key[:ALGORITHMS_DATA[self.crypto_algorithm][0]]
		iv = temp_key[ALGORITHMS_DATA[self.crypto_algorithm][0]:][:ALGORITHMS_DATA[self.crypto_algorithm][3]]
		cipher = ALGORITHMS_DATA[self.crypto_algorithm][1](crypt_key, mode = ALGORITHMS_DATA[self.crypto_algorithm][2], iv = iv)
		
		cleartext = cipher.decrypt(self.data)
		key_dec = cleartext[-64:]
		hmac_salt = cleartext[:16]
		hmac_res = cleartext[16:][:ALGORITHMS_DATA[self.hash_algorithm][0]]
		
		hmac_key = hmac.new(key, hmac_salt, hash_type).digest()
		hmac_calc = hmac.new(hmac_key, key_dec, hash_type).digest()
		#print(hmac_calc)
		#print(hmac_res)
		if hmac_calc[:ALGORITHMS_DATA[self.hash_algorithm][0]] == hmac_res:
			return key_dec
		else:
			return None
		
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
	
		