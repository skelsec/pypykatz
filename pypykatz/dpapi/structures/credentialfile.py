#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import enum

from pypykatz.dpapi.structures.blob import DPAPI_BLOB

class CredentialFile:
	"""
	"""
	def __init__(self):
		self.version = None
		self.size = None
		self.unk = None
		self.data = None
		
		#not in the spec
		self.blob = None
		
	@staticmethod
	def from_bytes(data):
		return CredentialFile.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = CredentialFile()
		sk.version = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.size = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.unk = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.data = buff.read(sk.size)
		sk.blob = DPAPI_BLOB.from_bytes(sk.data)
		return sk
		
	def __str__(self):
		t = '== CredentialFile ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class CREDENTIAL_ATTRIBUTE:
	"""
	"""
	def __init__(self):
		self.flags = None
		self.keyword_length = None
		self.keyword = None
		self.data_length = None
		self.data = None
		
	@staticmethod
	def from_bytes(data):
		return CREDENTIAL_ATTRIBUTE.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = CREDENTIAL_ATTRIBUTE()		
		sk.flags = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.keyword_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.keyword = buff.read(sk.keyword_length)
		try:
			sk.keyword = sk.keyword.decode('utf-16-le')
		except:
			pass
		sk.data_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.data = buff.read(sk.data_length)
		return sk
		
	def to_text(self):
		t = ''
		if len(self.keyword) > 0:
			t += 'keyword: %s\r\n' % str(self.keyword)
		if len(self.data) > 0:
			t += 'data: %s\r\n' % str(self.data)
		return t
		
	def __str__(self):
		t = '== CREDENTIAL_ATTRIBUTE ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
		
class CREDENTIAL_BLOB:
	"""
	"""
	def __init__(self):
		self.flags = None
		self.size = None
		self.unk0 = None
		self.type = None
		self.flags2 = None
		self.last_written = None
		self.unk1 = None
		self.persist = None
		self.attributes_count = None
		self.unk2 = None
		self.target_length = None
		self.target = None
		self.target_alias_length = None
		self.target_alias = None
		self.description_length = None
		self.description = None
		self.unknown3_length = None
		self.unknown3 = None
		self.username_length = None
		self.username = None
		self.unknown4_length = None
		self.unknown4 = None
		
		self.attributes = []
		
		
		
	@staticmethod
	def from_bytes(data):
		return CREDENTIAL_BLOB.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = CREDENTIAL_BLOB()		
		sk.flags = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.size = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.unk0 = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.type = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.flags2 = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.last_written = int.from_bytes(buff.read(8), 'little', signed = False)
		sk.unk1 = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.persist = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.attributes_count = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.unk2 = int.from_bytes(buff.read(8), 'little', signed = False)
		sk.target_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.target = buff.read(sk.target_length)
		if sk.target_length > 0:
			try:
				sk.target = sk.target.decode('utf-16-le')
			except:
				pass
		sk.target_alias_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.target_alias = buff.read(sk.target_alias_length)
		if sk.target_alias_length > 0:
			try:
				sk.target_alias = sk.target_alias.decode('utf-16-le')
			except:
				pass
		sk.description_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.description = buff.read(sk.description_length)
		if sk.description_length > 0:
			try:
				sk.description = sk.description.decode('utf-16-le')
			except:
				pass
		sk.unknown3_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.unknown3 = buff.read(sk.unknown3_length)
		sk.username_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.username = buff.read(sk.username_length)
		if sk.username_length > 0:
			try:
				sk.username = sk.username.decode('utf-16-le')
			except:
				pass
		sk.unknown4_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.unknown4 = buff.read(sk.unknown4_length)
		
		for _ in range(sk.attributes_count):
			attr = CREDENTIAL_ATTRIBUTE.from_buffer(buff)
			sk.attributes.append(attr)
		
		return sk
		
	def to_text(self):	
		t = ''
		t += 'last_written : %s\r\n' %  self.last_written
		if len(self.target) > 0:
			t += 'target : %s\r\n' %  str(self.target)
		if len(self.target_alias) > 0:
			t += 'target_alias : %s\r\n' %  str(self.target_alias)
		if len(self.description) > 0:
			t += 'description : %s\r\n' %  str(self.description)
		if len(self.unknown3) > 0:
			t += 'unknown3 : %s\r\n' %  str(self.unknown3)
		if len(self.username) > 0:
			t += 'username : %s\r\n' %  str(self.username)
		if len(self.unknown4) > 0:
			t += 'unknown4 : %s\r\n' %  str(self.unknown4)
		for attr in self.attributes:
			t += 'ATTRIBUTE\r\n'
			t += attr.to_text()
		return t
		
	def __str__(self):
		t = '== CREDENTIAL_BLOB ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
