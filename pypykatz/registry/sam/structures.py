#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io

class DOMAIN_ACCOUNT_F:
	def __init__(self):
		self.revision = None
		self.unk1 = None
		self.creation_time = None
		self.domain_modified_count = None
		self.max_pw_age = None
		self.min_pw_age = None
		self.force_logoff = None
		self.lockout_duration = None
		self.lockout_observation_window = None
		self.unk2 = None
		self.next_rid = None
		self.pw_properties = None
		self.min_pw_length = None
		self.pw_history_length = None
		self.lockout_treshold = None
		self.unk3 = None
		self.server_state = None
		self.server_role = None
		self.uas_compatibility_req = None
		self.unk4 = None
		self.key_0 = None
	
	@staticmethod
	def from_bytes(data):
		return DOMAIN_ACCOUNT_F.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		df = DOMAIN_ACCOUNT_F()
		df.revision = int.from_bytes(buff.read(4), 'little', signed = False)
		df.unk1 = int.from_bytes(buff.read(4), 'little', signed = False)
		df.creation_time = int.from_bytes(buff.read(8), 'little', signed = False)
		df.domain_modified_count = int.from_bytes(buff.read(8), 'little', signed = False)
		df.max_pw_age = int.from_bytes(buff.read(8), 'little', signed = False)
		df.min_pw_age = int.from_bytes(buff.read(8), 'little', signed = False)
		df.force_logoff = int.from_bytes(buff.read(8), 'little', signed = False)
		df.lockout_duration = int.from_bytes(buff.read(8), 'little', signed = False)
		df.lockout_observation_window = int.from_bytes(buff.read(8), 'little', signed = False)
		df.unk2 = int.from_bytes(buff.read(8), 'little', signed = False)
		df.next_rid = int.from_bytes(buff.read(4), 'little', signed = False)
		df.pw_properties = int.from_bytes(buff.read(4), 'little', signed = False)
		df.min_pw_length = int.from_bytes(buff.read(2), 'little', signed = False)
		df.pw_history_length = int.from_bytes(buff.read(2), 'little', signed = False)
		df.lockout_treshold = int.from_bytes(buff.read(2), 'little', signed = False)
		df.unk3 = int.from_bytes(buff.read(2), 'little', signed = False)
		df.server_state = int.from_bytes(buff.read(4), 'little', signed = False)
		df.server_role = int.from_bytes(buff.read(2), 'little', signed = False)
		df.uas_compatibility_req = int.from_bytes(buff.read(2), 'little', signed = False)
		df.unk4 = int.from_bytes(buff.read(8), 'little', signed = False)
		
		pos = buff.tell()
		marker = buff.read(1)
		buff.seek(pos,0)
		if marker == b'\x01':
			df.key_0 = SAM_KEY_DATA.from_buffer(buff)
		elif marker == b'\x02':
			df.key_0 = SAM_KEY_DATA_AES.from_buffer(buff)
		return df
		
	def __str__(self):
		t = '== DOMAIN_ACCOUNT_F ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class SAM_KEY_DATA:
	def __init__(self):
		self.revision = None
		self.length = None
		self.salt = None
		self.key = None
		self.checksum = None
		self.reserved = None
	
	@staticmethod
	def from_bytes(data):
		return SAM_KEY_DATA.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = SAM_KEY_DATA()
		sk.revision = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.salt = buff.read(16)
		sk.key = buff.read(16)
		sk.checksum = buff.read(16)
		sk.reserved = int.from_bytes(buff.read(8), 'little', signed = False)
		return sk
		
	def __str__(self):
		t = '== SAM_KEY_DATA ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class SAM_KEY_DATA_AES:
	def __init__(self):
		self.revision = None
		self.length = None
		self.checksum_length = None
		self.data_length = None
		self.salt = None
		self.data = None
	
	@staticmethod
	def from_bytes(data):
		return SAM_KEY_DATA_AES.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = SAM_KEY_DATA_AES()
		sk.revision = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.checksum_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.data_length = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.salt = buff.read(16)
		sk.data = buff.read(sk.data_length)
		return sk
		
	def __str__(self):
		t = '== SAM_KEY_DATA_AES ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class USER_ACCOUNT_V:
	def __init__(self):
		self.Unknown = None 
		self.NameOffset = None 
		self.NameLength = None 
		self.Unknown2 = None 
		self.FullNameOffset = None 
		self.FullNameLength = None 
		self.Unknown3 = None 
		self.CommentOffset = None 
		self.CommentLength = None 
		self.Unknown31 = None 
		self.UserCommentOffset = None 
		self.UserCommentLength = None 
		self.Unknown4 = None 
		self.Unknown5 = None 
		self.HomeDirOffset = None 
		self.HomeDirLength = None 
		self.Unknown6 = None 
		self.HomeDirConnectOffset = None 
		self.HomeDirConnectLength = None 
		self.Unknown7 = None 
		self.ScriptPathOffset = None 
		self.ScriptPathLength = None 
		self.Unknown8 = None 
		self.ProfilePathOffset = None 
		self.ProfilePathLength = None 
		self.Unknown9 = None 
		self.WorkstationsOffset = None 
		self.WorkstationsLength = None 
		self.Unknown10 = None 
		self.HoursAllowedOffset = None 
		self.HoursAllowedLength = None 
		self.Unknown11 = None 
		self.Unknown12 = None 
		self.LMHashOffset = None 
		self.LMHashLength = None 
		self.Unknown13 = None 
		self.NTHashOffset = None 
		self.NTHashLength = None 
		self.Unknown14 = None 
		self.Unknown15 = None 
		self.Data = None
		
		self.name = None
		self.fullname = None
		self.comment = None
		self.usercomment = None
		self.homedir = None
		self.homedir_connect = None
		self.script_path = None
		self.profile_path = None
		self.workstations = None
		self.hoursallowed = None
		self.LM_hash = None
		self.NT_hash = None
		
	@staticmethod
	def from_bytes(data):
		return USER_ACCOUNT_V.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		uac = USER_ACCOUNT_V()		
		uac.Unknown = buff.read(12) 
		uac.NameOffset = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.NameLength = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown2 = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.FullNameOffset = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.FullNameLength = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown3 = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.CommentOffset = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.CommentLength = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown31 = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.UserCommentOffset = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.UserCommentLength = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown4 = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown5 = buff.read(12)  
		uac.HomeDirOffset = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.HomeDirLength = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.Unknown6 = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.HomeDirConnectOffset = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.HomeDirConnectLength = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.Unknown7 = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.ScriptPathOffset = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.ScriptPathLength = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.Unknown8 = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.ProfilePathOffset = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.ProfilePathLength = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.Unknown9 = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.WorkstationsOffset = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.WorkstationsLength = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.Unknown10 = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.HoursAllowedOffset = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.HoursAllowedLength = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.Unknown11 = int.from_bytes(buff.read(4), 'little', signed = False)  
		uac.Unknown12 = buff.read(12) 
		uac.LMHashOffset = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.LMHashLength = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown13 = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.NTHashOffset = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.NTHashLength = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown14 = int.from_bytes(buff.read(4), 'little', signed = False) 
		uac.Unknown15 = buff.read(24)
		data_offset = buff.tell()
		
		if uac.NameLength > 0:
			buff.seek(data_offset +uac.NameOffset)
			uac.name = buff.read(uac.NameLength).decode('utf-16-le')
		
		if uac.FullNameLength > 0:
			buff.seek(data_offset +uac.FullNameOffset)
			uac.fullname = buff.read(uac.FullNameLength).decode('utf-16-le')
		if uac.CommentLength > 0:
			buff.seek(data_offset +uac.CommentOffset)
			uac.comment = buff.read(uac.CommentLength).decode('utf-16-le')
		if uac.UserCommentLength > 0:
			buff.seek(data_offset +uac.UserCommentOffset)
			uac.usercomment = buff.read(uac.UserCommentLength).decode('utf-16-le')
		if uac.HomeDirLength > 0:
			buff.seek(data_offset +uac.HomeDirOffset)
			uac.homedir = buff.read(uac.HomeDirLength).decode('utf-16-le')
		if uac.HomeDirConnectLength > 0:
			buff.seek(data_offset +uac.HomeDirConnectOffset)
			uac.homedir_connect = buff.read(uac.HomeDirConnectLength).decode('utf-16-le')
		
		if uac.ScriptPathLength > 0:
			buff.seek(data_offset +uac.ScriptPathOffset)
			uac.script_path = buff.read(uac.ScriptPathLength).decode('utf-16-le')
		if uac.ProfilePathLength > 0:
			buff.seek(data_offset +uac.ProfilePathOffset)
			uac.profile_path = buff.read(uac.ProfilePathLength).decode('utf-16-le')
		if uac.WorkstationsLength > 0:
			buff.seek(data_offset +uac.WorkstationsOffset)
			uac.workstations = buff.read(uac.WorkstationsLength).decode('utf-16-le')
		if uac.HoursAllowedLength > 0:
			buff.seek(data_offset +uac.HoursAllowedOffset)
			uac.hoursallowed = buff.read(uac.HoursAllowedLength)
		
		if uac.NTHashLength > 0:
			buff.seek(data_offset + uac.NTHashOffset + 2)
			if buff.read(1) == b'\x01':
				if uac.NTHashLength == 20:
					buff.seek(data_offset + uac.NTHashOffset)
					uac.NT_hash = SAM_HASH.from_bytes(buff.read(uac.NTHashLength))
				
				if uac.LMHashLength == 20:
					buff.seek(data_offset + uac.LMHashOffset)
					uac.LM_hash = SAM_HASH.from_bytes(buff.read(uac.LMHashLength))
		
			else:
				if uac.LMHashLength == 24:
					buff.seek(data_offset + uac.LMHashOffset)
					uac.LM_hash = SAM_HASH_AES.from_bytes(buff.read(uac.LMHashLength))
				
				buff.seek(data_offset  +uac.NTHashOffset)
				uac.NT_hash = SAM_HASH_AES.from_bytes(buff.read(uac.NTHashLength))
				
		return uac
		
	def __str__(self):
		t = '== USER_ACCOUNT_V ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
		
class SAM_HASH:
	def __init__(self):
		self.pekID = None
		self.revision = None
		self.hash = None
	
	@staticmethod
	def from_bytes(data):
		return SAM_HASH.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = SAM_HASH()
		sk.pekID = int.from_bytes(buff.read(2), 'little', signed = False) 
		sk.revision = int.from_bytes(buff.read(2), 'little', signed = False) 
		sk.hash = buff.read(16)
		return sk
		
	def __str__(self):
		t = '== SAM_HASH ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class SAM_HASH_AES:
	def __init__(self):
		self.pekID = None
		self.revision = None
		self.data_offset = None
		self.salt = None
		self.data = None
	
	@staticmethod
	def from_bytes(data):
		return SAM_HASH_AES.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = SAM_HASH_AES()
		sk.pekID = int.from_bytes(buff.read(2), 'little', signed = False) 
		sk.revision = int.from_bytes(buff.read(2), 'little', signed = False) 
		sk.data_offset = int.from_bytes(buff.read(4), 'little', signed = False)
		sk.salt = buff.read(16)
		sk.data = buff.read()
		return sk
		
	def __str__(self):
		t = '== SAM_HASH_AES ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
