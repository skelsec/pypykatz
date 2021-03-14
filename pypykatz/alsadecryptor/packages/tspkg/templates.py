#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

#import io
#from minidump.win_datatypes import *
from pypykatz.commons.common import KatzSystemArchitecture, WindowsBuild, WindowsMinBuild
from pypykatz.alsadecryptor.win_datatypes import KIWI_GENERIC_PRIMARY_CREDENTIAL, POINTER, PVOID, LUID
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class TspkgTemplate(PackageTemplate):
	def __init__(self):
		super().__init__('Tspkg')
		self.signature = None
		self.avl_offset = None
		self.credential_struct = None
		
	@staticmethod
	def get_template(sysinfo):
		template = TspkgTemplate()
		if sysinfo.architecture == KatzSystemArchitecture.X64:
			template.signature = b'\x48\x83\xec\x20\x48\x8d\x0d'
			template.avl_offset = 7
			
			if sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
				template.credential_struct = KIWI_TS_CREDENTIAL_x64
				
			elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1607.value:
				template.credential_struct = KIWI_TS_CREDENTIAL_1607_x64
				
			else:
				#currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (sysinfo.architecture, sysinfo.buildnumber))
			
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x8b\xff\x55\x8b\xec\x51\x56\xbe'
				template.avl_offset = 8
				template.credential_struct = KIWI_TS_CREDENTIAL
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x8b\xff\x53\xbb'
				template.avl_offset = 4
				template.credential_struct = KIWI_TS_CREDENTIAL
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
				template.signature = b'\x8b\xff\x57\xbf'
				template.avl_offset = 4
				template.credential_struct = KIWI_TS_CREDENTIAL
				
			elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1607.value:
				template.signature = b'\x8b\xff\x57\xbf'
				template.avl_offset = 4
				template.credential_struct = KIWI_TS_CREDENTIAL_1607
			
		else:
			raise Exception('Unknown architecture! %s' % sysinfo.architecture)

		template.log_template('credential_struct', template.credential_struct)
			
		return template
	

class PKIWI_TS_PRIMARY_CREDENTIAL(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_TS_PRIMARY_CREDENTIAL()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_TS_PRIMARY_CREDENTIAL
		return p
	
class KIWI_TS_PRIMARY_CREDENTIAL:
	def __init__(self):
		self.unk0 = None
		self.credentials = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_TS_PRIMARY_CREDENTIAL()
		res.unk0 = await PVOID.load(reader) #	// lock ?
		res.credentials = await KIWI_GENERIC_PRIMARY_CREDENTIAL.load(reader)
		return res
	 

class KIWI_TS_CREDENTIAL:
	def __init__(self,):
		self.unk0 = None
		self.LocallyUniqueIdentifier = None
		self.unk1 = None
		self.unk2 = None
		self.pTsPrimary  = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_TS_CREDENTIAL()
		res.unk0 = await reader.read(64)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		await reader.align()
		res.unk1 = await PVOID.load(reader)
		res.unk2 = await PVOID.load(reader)
		res.pTsPrimary  = await PKIWI_TS_PRIMARY_CREDENTIAL.load(reader)
		return res
	
class KIWI_TS_CREDENTIAL_x64:
	def __init__(self):
		self.unk0 = None 
		self.LocallyUniqueIdentifier = None
		self.unk1 = None
		self.unk2 = None
		self.pTsPrimary = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_TS_CREDENTIAL_x64()
		res.unk0 = await reader.read(108) 
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		await reader.align()
		res.unk1 = await PVOID.load(reader)
		res.unk2 = await PVOID.load(reader)
		res.pTsPrimary  = await PKIWI_TS_PRIMARY_CREDENTIAL.load(reader)
		return res

class KIWI_TS_CREDENTIAL_1607:
	def __init__(self):
		self.unk0 = None
		self.LocallyUniqueIdentifier = None
		self.unk1 = None
		self.unk2 = None
		self.pTsPrimary = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_TS_CREDENTIAL_1607()
		res.unk0 = await reader.read(68)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		await reader.align()
		res.unk1 = await PVOID.load(reader)
		res.unk2 = await PVOID.load(reader)
		res.pTsPrimary  = await PKIWI_TS_PRIMARY_CREDENTIAL.load(reader)
		return res
	

class KIWI_TS_CREDENTIAL_1607_x64:
	def __init__(self):
		self.unk0 = None
		self.LocallyUniqueIdentifier = None
		self.unk1 = None
		self.unk2 = None
		self.pTsPrimary = None

	@staticmethod
	async def load(reader):
		res = KIWI_TS_CREDENTIAL_1607_x64()
		res.unk0 = await reader.read(112) 
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		await reader.align()
		res.unk1 = await PVOID.load(reader)
		res.unk2 = await PVOID.load(reader)
		res.pTsPrimary  = await PKIWI_TS_PRIMARY_CREDENTIAL.load(reader)
		return res