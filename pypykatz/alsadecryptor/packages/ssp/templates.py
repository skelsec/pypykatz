#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from pypykatz.alsadecryptor.win_datatypes import ULONG, LUID, KIWI_GENERIC_PRIMARY_CREDENTIAL, POINTER
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class SspTemplate(PackageTemplate):
	def __init__(self):
		super().__init__('Ssp')
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
	
	@staticmethod
	def get_template(sysinfo):
		template = SspTemplate()
		template.list_entry = PKIWI_SSP_CREDENTIAL_LIST_ENTRY
		template.log_template('list_entry', template.list_entry)
		
		if sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\xc7\x43\x24\x43\x72\x64\x41\xff\x15'
				template.first_entry_offset = 16
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\xc7\x47\x24\x43\x72\x64\x41\x48\x89\x47\x78\xff\x15'
				template.first_entry_offset = 20
				
			elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x24\x43\x72\x64\x41\xff\x15'
				template.first_entry_offset = 14
			
			else:
				#currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s sysinfo.buildnumber: %s' % (sysinfo.architecture, sysinfo.buildnumber))
			
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			template.signature = b'\x1c\x43\x72\x64\x41\xff\x15'
			template.first_entry_offset = 12
			
		else:
			raise Exception('Unknown architecture! %s' % sysinfo.architecture)

			
		return template
	

class PKIWI_SSP_CREDENTIAL_LIST_ENTRY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_SSP_CREDENTIAL_LIST_ENTRY()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_SSP_CREDENTIAL_LIST_ENTRY
		return p
		
class KIWI_SSP_CREDENTIAL_LIST_ENTRY:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.References = None
		self.CredentialReferences = None
		self.LogonId = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.credentials = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_SSP_CREDENTIAL_LIST_ENTRY()
		res.Flink = await PKIWI_SSP_CREDENTIAL_LIST_ENTRY.load(reader)
		res.Blink = await PKIWI_SSP_CREDENTIAL_LIST_ENTRY.load(reader)
		res.References = await ULONG.loadvalue(reader)
		res.CredentialReferences = await ULONG.loadvalue(reader)
		res.LogonId = await LUID.loadvalue(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await ULONG.loadvalue(reader)
		await reader.align()
		res.credentials = await KIWI_GENERIC_PRIMARY_CREDENTIAL.load(reader)
		return res