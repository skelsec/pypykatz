#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
#from minidump.win_datatypes import *
from pypykatz.commons.common import KatzSystemArchitecture
from pypykatz.alsadecryptor.win_datatypes import POINTER, ULONG, \
	KIWI_GENERIC_PRIMARY_CREDENTIAL, PVOID, DWORD, LUID, LSA_UNICODE_STRING
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class LiveSspTemplate(PackageTemplate):
	def __init__(self):
		super().__init__('LiveSsp')
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
		
	@staticmethod
	def get_template(sysinfo):
		template = LiveSspTemplate()
		template.list_entry = PKIWI_LIVESSP_LIST_ENTRY
		template.log_template('list_entry', template.list_entry)
		
		if sysinfo.architecture == KatzSystemArchitecture.X64:	
			template.signature = b'\x74\x25\x8b'
			template.first_entry_offset = -7
			
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			template.signature = b'\x8b\x16\x39\x51\x24\x75\x08'
			template.first_entry_offset = -8
			
		else:
			raise Exception('Unknown architecture! %s' % sysinfo.architecture)

			
		return template
	

class PKIWI_LIVESSP_PRIMARY_CREDENTIAL(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_LIVESSP_PRIMARY_CREDENTIAL()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_LIVESSP_PRIMARY_CREDENTIAL
		return p
		
class KIWI_LIVESSP_PRIMARY_CREDENTIAL:
	def __init__(self):
		self.isSupp = None
		self.unk0 = None
		self.credentials = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_LIVESSP_PRIMARY_CREDENTIAL()
		res.isSupp = await ULONG.loadvalue(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.credentials = await KIWI_GENERIC_PRIMARY_CREDENTIAL.load(reader)
		return res


class PKIWI_LIVESSP_LIST_ENTRY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_LIVESSP_LIST_ENTRY()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_LIVESSP_LIST_ENTRY
		return p
		
class KIWI_LIVESSP_LIST_ENTRY:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.LocallyUniqueIdentifier = None
		self.UserName = None
		self.unk7 = None
		self.suppCreds = None

	@staticmethod
	async def load(reader):
		res = KIWI_LIVESSP_LIST_ENTRY()
		res.Flink = await PKIWI_LIVESSP_LIST_ENTRY.load(reader)
		res.Blink = await PKIWI_LIVESSP_LIST_ENTRY.load(reader)
		res.unk0 = await PVOID.load(reader)
		res.unk1 = await PVOID.load(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.unk4 = await DWORD.loadvalue(reader)
		res.unk5 = await DWORD.loadvalue(reader)
		res.unk6 = await PVOID.load(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.unk7 = await PVOID.load(reader)
		res.suppCreds = await PKIWI_LIVESSP_PRIMARY_CREDENTIAL.load(reader)
		return res