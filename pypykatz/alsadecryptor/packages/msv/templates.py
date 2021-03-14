#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from pypykatz.alsadecryptor.win_datatypes import BOOLEAN, HANDLE, USHORT, ULONG, LSA_UNICODE_STRING, LSAISO_DATA_BLOB, \
	BYTE, PVOID, WORD, DWORD, POINTER, LUID, PSID, ANSI_STRING
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class MsvTemplate(PackageTemplate):
	def __init__(self):
		super().__init__('Msv')
		
		self.signature = None
		self.first_entry_offset = None
		self.offset2 = None
		
		self.list_entry = None
		self.encrypted_credentials_list_struct = None
		self.encrypted_credential_struct = None
		self.decrypted_credential_struct = None
	
	@staticmethod
	def get_template(sysinfo):
		template = MsvTemplate()
		template.encrypted_credentials_list_struct = KIWI_MSV1_0_CREDENTIAL_LIST
		template.log_template('encrypted_credentials_list_struct', template.encrypted_credentials_list_struct)
		template.encrypted_credential_struct = KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
		template.log_template('encrypted_credential_struct', template.encrypted_credential_struct)
		#identify credential session list structure to be used
		if sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
			template.list_entry = PKIWI_MSV1_0_LIST_51
			
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
			template.list_entry = PKIWI_MSV1_0_LIST_52
		
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
			template.list_entry = PKIWI_MSV1_0_LIST_60
		
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
			#do not do that :)
			if sysinfo.msv_dll_timestamp >  0x53480000:
				template.list_entry = PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ
			else:
				template.list_entry = PKIWI_MSV1_0_LIST_61	
		
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
			#template.list_entry = PKIWI_MSV1_0_LIST_62
			if sysinfo.msv_dll_timestamp >  0x53480000:
				template.list_entry = PKIWI_MSV1_0_LIST_63
			else:
				template.list_entry = PKIWI_MSV1_0_LIST_62
		
		else:
			template.list_entry = PKIWI_MSV1_0_LIST_63
		
		template.log_template('list_entry', template.list_entry)
		if sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_DEC
		elif sysinfo.buildnumber < WindowsBuild.WIN_10_1511.value:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_10_OLD_DEC
		elif sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_10_DEC
		else:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC
		
		template.log_template('decrypted_credential_struct', template.decrypted_credential_struct)
			
		if sysinfo.architecture == KatzSystemArchitecture.X64:
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x4c\x8b\xdf\x49\xc1\xe3\x04\x48\x8b\xcb\x4c\x03\xd8'
				template.first_entry_offset = -4
				template.offset2 = 0
				
			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x4c\x8b\xdf\x49\xc1\xe3\x04\x48\x8b\xcb\x4c\x03\xd8'
				template.first_entry_offset = -4
				template.offset2 = -45
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.signature = b'\x33\xff\x45\x85\xc0\x41\x89\x75\x00\x4c\x8b\xe3\x0f\x84'
				template.first_entry_offset = 21#-4
				template.offset2 = -4
				
			elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x33\xf6\x45\x89\x2f\x4c\x8b\xf3\x85\xff\x0f\x84'
				template.first_entry_offset = 19
				template.offset2 = -4	
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74'
				template.first_entry_offset = 16
				template.offset2 = -4	
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x8b\xde\x48\x8d\x0c\x5b\x48\xc1\xe1\x05\x48\x8d\x05'
				template.first_entry_offset = 36
				template.offset2 = -6	
				
			elif WindowsBuild.WIN_10_1507.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1703.value:
				#1503 and 1603
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74'
				template.first_entry_offset = 16
				template.offset2 = -4

			elif WindowsBuild.WIN_10_1703.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1803.value:
				#1703
				template.signature = b'\x33\xff\x45\x89\x37\x48\x8b\xf3\x45\x85\xc9\x74'
				template.first_entry_offset = 23
				template.offset2 = -4
			
			elif WindowsBuild.WIN_10_1803.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1903.value:
				#1803
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc9\x74'
				template.first_entry_offset = 23
				template.offset2 = -4
				
			else:
				#1903
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74'
				template.first_entry_offset = 23
				template.offset2 = -4
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\xff\x50\x10\x85\xc0\x0f\x84'
				template.first_entry_offset = 24
				template.offset2 = 0

		
			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x89\x71\x04\x89\x30\x8d\x04\xbd'
				template.first_entry_offset = -11
				template.offset2 = -43

			
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x89\x71\x04\x89\x30\x8d\x04\xbd'
				template.first_entry_offset = -11
				template.offset2 = -42
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x8b\x45\xf8\x8b\x55\x08\x8b\xde\x89\x02\x89\x5d\xf0\x85\xc9\x74'
				template.first_entry_offset = 18
				template.offset2 = -4
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x8b\x4d\xe4\x8b\x45\xf4\x89\x75\xe8\x89\x01\x85\xff\x74'	
				template.first_entry_offset = 16
				template.offset2 = -4
			
			elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x8b\x4d\xe8\x8b\x45\xf4\x89\x75\xec\x89\x01\x85\xff\x74'
				template.first_entry_offset = 16
				template.offset2 = -4
			else:
				raise Exception('Could not identify template! sysinfo.buildnumber: %d' % sysinfo.buildnumber)
		
		else:
			raise Exception('Unknown Architecture: %s , Build number %s' % (sysinfo.architecture, sysinfo.buildnumber))
			
		
		return template
	
	
class MSV1_0_PRIMARY_CREDENTIAL_STRANGE_DEC:
	#this structure doesnt have username nor domainname, but has credentials :S
	#starts with 
	size = 0x60
	def __init__(self):
		self.unk1 = None
		self.unk2 = None
		self.unk_tag = None
		self.unk_remaining_size = None
		self.LengthOfNtOwfPassword = None
		self.NtOwfPassword = None
		self.LengthOfShaOwfPassword = None
		self.ShaOwPassword = None
		
		self.LogonDomainName = None
		self.UserName = None
		self.LmOwfPassword = None
		self.isNtOwfPassword = None
		self.isLmOwfPassword = None
		self.isShaOwPassword = None

	@staticmethod
	async def load(reader):
		res = MSV1_0_PRIMARY_CREDENTIAL_STRANGE_DEC()
		res.unk1 = await USHORT.loadvalue(reader)
		res.unk2 = await USHORT.loadvalue(reader)
		res.unk_tag = await reader.read(4) #0xcccccc
		res.unk_remaining_size = await ULONG.loadvalue(reader)
		await reader.read(40)
		res.LengthOfNtOwfPassword = await ULONG.loadvalue(reader)
		res.NtOwfPassword = await reader.read(16)
		res.LengthOfShaOwfPassword = await ULONG.loadvalue(reader)
		res.ShaOwPassword = await reader.read(20)
		
		res.LogonDomainName = None
		res.UserName = None
		res.LmOwfPassword = None
		res.isNtOwfPassword = None
		res.isLmOwfPassword = None
		res.isShaOwPassword = None
		return res 
		
class MSV1_0_PRIMARY_CREDENTIAL_DEC:
	def __init__(self):
		self.LogonDomainName = None
		self.UserName = None
		self.NtOwfPassword = None
		self.LmOwfPassword = None
		self.ShaOwPassword = None
		self.isNtOwfPassword = None
		self.isLmOwfPassword = None
		self.isShaOwPassword = None

	@staticmethod
	async def load(reader):
		res = MSV1_0_PRIMARY_CREDENTIAL_DEC()
		res.LogonDomainName = await LSA_UNICODE_STRING.load(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.NtOwfPassword = await reader.read(16)
		res.LmOwfPassword = await reader.read(16)
		res.ShaOwPassword = await reader.read(20)
		res.isNtOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isLmOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isShaOwPassword = await BOOLEAN.loadvalue(reader)
		return res 

class MSV1_0_PRIMARY_CREDENTIAL_10_OLD_DEC:
	def __init__(self):
		self.LogonDomainName = None
		self.UserName = None
		self.isIso = None
		self.isNtOwfPassword = None
		self.isLmOwfPassword = None
		self.isShaOwPassword = None
		self.align0 = None
		self.align1 = None
		self.NtOwfPassword = None
		self.LmOwfPassword = None
		self.ShaOwPassword = None
	
	@staticmethod
	async def load(reader):
		res = MSV1_0_PRIMARY_CREDENTIAL_10_OLD_DEC()
		res.LogonDomainName = await LSA_UNICODE_STRING.load(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.isIso = await BOOLEAN.loadvalue(reader)
		res.isNtOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isLmOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isShaOwPassword = await BOOLEAN.loadvalue(reader)
		res.align0 = await BYTE.loadvalue(reader)
		res.align1 = await BYTE.loadvalue(reader)
		res.NtOwfPassword = await reader.read(16)
		res.LmOwfPassword = await reader.read(16)
		res.ShaOwPassword = await reader.read(20)
		return res 
		
class MSV1_0_PRIMARY_CREDENTIAL_10_DEC:
	def __init__(self):
		self.LogonDomainName =  None
		self.UserName = None
		self.isIso = None
		self.isNtOwfPassword = None
		self.isLmOwfPassword = None
		self.isShaOwPassword = None
		self.align0 = None
		self.align1 = None
		self.align2 = None
		self.align3 = None
		self.NtOwfPassword = None
		self.LmOwfPassword = None
		self.ShaOwPassword = None
	
	@staticmethod
	async def load(reader):
		res = MSV1_0_PRIMARY_CREDENTIAL_10_DEC()
		res.LogonDomainName =  await LSA_UNICODE_STRING.load(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.isIso = await BOOLEAN.loadvalue(reader)
		res.isNtOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isLmOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isShaOwPassword = await BOOLEAN.loadvalue(reader)
		res.align0 = await BYTE.loadvalue(reader)
		res.align1 = await BYTE.loadvalue(reader)
		res.align2 = await BYTE.loadvalue(reader)
		res.align3 = await BYTE.loadvalue(reader)
		res.NtOwfPassword = await reader.read(16)
		res.LmOwfPassword = await reader.read(16)
		res.ShaOwPassword = await reader.read(20)
		return res 
		
class MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC:
	def __init__(self):
		self.LogonDomainName = None
		self.UserName = None
		self.pNtlmCredIsoInProc = None
		self.isIso = None
		self.isNtOwfPassword = None
		self.isLmOwfPassword = None
		self.isShaOwPassword = None
		self.isDPAPIProtected = None
		self.align0 = None
		self.align1 = None
		self.align2 = None
		self.unkD = None
		# stuff to be done! #pragma pack(push, 2)
		self.isoSize = None
		self.DPAPIProtected = None
		self.align3 = None
		# stuff to be done! #pragma pack(pop) 
		self.NtOwfPassword = None
		self.LmOwfPassword = None
		self.ShaOwPassword = None
	
	@staticmethod
	async def load(reader):
		res = MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC()
		res.LogonDomainName =  await LSA_UNICODE_STRING.load(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.pNtlmCredIsoInProc = await PVOID.loadvalue(reader)
		res.isIso = await BOOLEAN.loadvalue(reader)
		res.isNtOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isLmOwfPassword = await BOOLEAN.loadvalue(reader)
		res.isShaOwPassword = await BOOLEAN.loadvalue(reader)
		res.isDPAPIProtected = await BOOLEAN.loadvalue(reader)
		res.align0 = await BYTE.loadvalue(reader)
		res.align1 = await BYTE.loadvalue(reader)
		res.align2 = await BYTE.loadvalue(reader)
		res.unkD = await DWORD.loadvalue(reader) # // 1/2
		# stuff to be done! #pragma pack(push, 2)
		res.isoSize = await WORD.loadvalue(reader) #// 0000
		res.DPAPIProtected = await reader.read(16)
		res.align3 = await DWORD.loadvalue(reader) #// 00000000
		# stuff to be done! #pragma pack(pop) 
		res.NtOwfPassword = await reader.read(16)
		res.LmOwfPassword = await reader.read(16)
		res.ShaOwPassword = await reader.read(20)
		return res 
		
class KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC:
	def __init__(self):
		self.Flink = None
		self.Primary = None
		self.encrypted_credentials = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC()
		res.Flink = await PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC.load(reader)
		res.Primary = await ANSI_STRING.load(reader)
		await reader.align()
		res.encrypted_credentials = await LSA_UNICODE_STRING.load(reader)
		return res
		
class PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
		return p

#class PKIWI_MSV1_0_CREDENTIAL_LIST(POINTER):
#	def __init__(self, reader):
#		super().__init__(reader, PKIWI_MSV1_0_CREDENTIAL_LIST)

class KIWI_MSV1_0_CREDENTIAL_LIST:
	def __init__(self):
		self.Flink = None
		self.AuthenticationPackageId = None
		self.PrimaryCredentials_ptr = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_CREDENTIAL_LIST()
		res.Flink = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.AuthenticationPackageId = await DWORD.loadvalue(reader)
		await reader.align()
		res.PrimaryCredentials_ptr = await PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC.load(reader)
		return res


class PKIWI_MSV1_0_CREDENTIAL_LIST(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_CREDENTIAL_LIST()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_CREDENTIAL_LIST
		return p
		
class PKIWI_MSV1_0_LIST_51(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_LIST_51()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_LIST_51
		return p
		
class KIWI_MSV1_0_LIST_51:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.LocallyUniqueIdentifier = None
		self.UserName = None
		self.Domaine = None
		self.unk0 = None
		self.unk1 = None
		self.pSid = None
		self.LogonType = None
		self.Session = None
		self.LogonTime = None
		self.LogonServer = None
		self.Credentials_list_ptr = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.CredentialManager = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_LIST_51()
		res.Flink = await PKIWI_MSV1_0_LIST_51.load(reader)
		res.Blink = await PKIWI_MSV1_0_LIST_51.load(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine = await LSA_UNICODE_STRING.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.pSid = await PSID.load(reader)
		res.LogonType = await ULONG.loadvalue(reader)
		res.Session = await ULONG.loadvalue(reader)
		await reader.align(8)
		t = t = await reader.read(8)
		res.LogonTime = int.from_bytes(t, byteorder = 'little', signed = False) #autoalign x86
		await reader.align()
		res.LogonServer = await LSA_UNICODE_STRING.load(reader)
		res.Credentials_list_ptr = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.unk19 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.unk23 = await ULONG.loadvalue(reader)
		await reader.align()
		res.CredentialManager = await PVOID.load(reader)
		return res

class PKIWI_MSV1_0_LIST_52(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_LIST_52()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_LIST_52
		return p
		
class KIWI_MSV1_0_LIST_52:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.LocallyUniqueIdentifier = None
		self.UserName = None
		self.Domaine = None
		self.unk0 = None
		self.unk1 = None
		self.pSid = None
		self.LogonType = None
		self.Session = None
		self.LogonTime = None
		self.LogonServer = None
		self.Credentials_list_ptr = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.CredentialManager = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_LIST_52()
		res.Flink = await PKIWI_MSV1_0_LIST_52.load(reader)
		res.Blink = await PKIWI_MSV1_0_LIST_52.load(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine = await LSA_UNICODE_STRING.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.pSid = await PSID.load(reader)
		res.LogonType = await ULONG.loadvalue(reader)
		res.Session = await ULONG.loadvalue(reader)
		await reader.align(8)
		t = await reader.read(8)
		res.LogonTime = int.from_bytes(t, byteorder = 'little', signed = False) #autoalign x86
		res.LogonServer = await LSA_UNICODE_STRING.load(reader)
		res.Credentials_list_ptr = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.unk19 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await ULONG.loadvalue(reader)
		await reader.align()
		res.CredentialManager = await PVOID.load(reader)
		return res

class PKIWI_MSV1_0_LIST_60(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_LIST_60()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_LIST_60
		return p

class KIWI_MSV1_0_LIST_60:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.hSemaphore6 = None
		self.unk7 = None
		self.hSemaphore8 = None
		self.unk9 = None
		self.unk10 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.LocallyUniqueIdentifier = None
		self.SecondaryLocallyUniqueIdentifier = None
		self.UserName = None
		self.Domaine = None
		self.unk14 = None
		self.unk15 = None
		self.pSid = None
		self.LogonType = None
		self.Session = None
		self.LogonTime = None
		self.LogonServer = None
		self.Credentials_list_ptr = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.CredentialManager = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_LIST_60()
		res.Flink = await PKIWI_MSV1_0_LIST_60.load(reader)
		res.Blink = await PKIWI_MSV1_0_LIST_60.load(reader)
		await reader.align()
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await PVOID.loadvalue(reader)
		res.unk3 = await ULONG.loadvalue(reader)
		res.unk4 = await ULONG.loadvalue(reader)
		res.unk5 = await ULONG.loadvalue(reader)
		await reader.align()
		res.hSemaphore6 = await HANDLE.loadvalue(reader)
		await reader.align()
		res.unk7 = await PVOID.loadvalue(reader)
		await reader.align()
		res.hSemaphore8 = await HANDLE.loadvalue(reader)
		await reader.align()
		res.unk9 = await PVOID.loadvalue(reader)
		await reader.align()
		res.unk10 = await PVOID.loadvalue(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		res.unk12 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk13 = await PVOID.loadvalue(reader)
		await reader.align()
		t = await reader.read(8)
		res.LocallyUniqueIdentifier = int.from_bytes(t, byteorder = 'little', signed = False)
		t = await reader.read(8)
		res.SecondaryLocallyUniqueIdentifier = int.from_bytes(t, byteorder = 'little', signed = False)
		await reader.align()
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine = await LSA_UNICODE_STRING.load(reader)
		res.unk14 = await PVOID.loadvalue(reader)
		res.unk15 = await PVOID.loadvalue(reader)
		res.pSid = await PSID.load(reader)
		res.LogonType = await ULONG.loadvalue(reader)
		res.Session = await ULONG.loadvalue(reader)
		await reader.align(8)
		t = await reader.read(8)
		res.LogonTime = int.from_bytes(t, byteorder = 'little', signed = False) #autoalign x86
		res.LogonServer = await LSA_UNICODE_STRING.load(reader)
		res.Credentials_list_ptr = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.unk19 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.unk23 = await ULONG.loadvalue(reader)
		await reader.align()
		res.CredentialManager = await PVOID.load(reader)
		return res

class PKIWI_MSV1_0_LIST_61(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_LIST_61()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_LIST_61
		return p
		
class KIWI_MSV1_0_LIST_61:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.hSemaphore6 = None
		self.unk7 = None
		self.hSemaphore8 = None
		self.unk9 = None
		self.unk10 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.LocallyUniqueIdentifier = None
		self.SecondaryLocallyUniqueIdentifier = None
		self.UserName = None
		self.Domaine = None
		self.unk14 = None
		self.unk15 = None
		self.pSid = None
		self.LogonType = None
		self.Session = None
		self.LogonTime = None
		self.LogonServer = None
		self.Credentials_list_ptr = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.CredentialManager = None


	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_LIST_61()
		res.Flink = await PKIWI_MSV1_0_LIST_61.load(reader)
		res.Blink = await PKIWI_MSV1_0_LIST_61.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await PVOID.loadvalue(reader)
		res.unk3 = await ULONG.loadvalue(reader)
		res.unk4 = await ULONG.loadvalue(reader)
		res.unk5 = await ULONG.loadvalue(reader)
		await reader.align()
		res.hSemaphore6 = await HANDLE.loadvalue(reader)
		res.unk7 = await PVOID.loadvalue(reader)
		res.hSemaphore8 = await HANDLE.loadvalue(reader)
		res.unk9 = await PVOID.loadvalue(reader)
		res.unk10 = await PVOID.loadvalue(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		res.unk12 = await ULONG.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.SecondaryLocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine = await LSA_UNICODE_STRING.load(reader)
		res.unk14 = await PVOID.loadvalue(reader)
		res.unk15 = await PVOID.loadvalue(reader)
		res.pSid = await PSID.load(reader)
		res.LogonType = await ULONG.loadvalue(reader)
		res.Session = await ULONG.loadvalue(reader)
		await reader.align(8)
		t = await reader.read(8)
		res.LogonTime = int.from_bytes(t, byteorder = 'little', signed = False) #autoalign x86
		res.LogonServer = await LSA_UNICODE_STRING.load(reader)
		res.Credentials_list_ptr = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await ULONG.loadvalue(reader)
		await reader.align()
		res.CredentialManager = await PVOID.load(reader)
		return res

class PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ
		return p
		
class KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.hSemaphore6 = None
		self.unk7 = None
		self.hSemaphore8 = None
		self.unk9 = None
		self.unk10 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.LocallyUniqueIdentifier = None
		self.SecondaryLocallyUniqueIdentifier = None
		self.waza = None
		self.UserName = None
		self.Domaine = None
		self.unk14 = None
		self.unk15 = None
		self.pSid = None
		self.LogonType = None
		self.Session = None
		self.LogonTime = None
		self.LogonServer = None
		self.Credentials_list_ptr = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.CredentialManager = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ()
		res.Flink = await PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ.load(reader)
		res.Blink = await PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await PVOID.loadvalue(reader)
		res.unk3 = await ULONG.loadvalue(reader)
		res.unk4 = await ULONG.loadvalue(reader)
		res.unk5 = await ULONG.loadvalue(reader)
		await reader.align()
		res.hSemaphore6 = await HANDLE.loadvalue(reader)
		res.unk7 = await PVOID.loadvalue(reader)
		res.hSemaphore8 = await HANDLE.loadvalue(reader)
		res.unk9 = await PVOID.loadvalue(reader)
		res.unk10 = await PVOID.loadvalue(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		res.unk12 = await ULONG.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.SecondaryLocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.waza = await reader.read(12)
		await reader.align()
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine = await LSA_UNICODE_STRING.load(reader)
		res.unk14 = await PVOID.loadvalue(reader)
		res.unk15 = await PVOID.loadvalue(reader)
		res.pSid = await PSID.load(reader)
		res.LogonType = await ULONG.loadvalue(reader)
		res.Session = await ULONG.loadvalue(reader)
		await reader.align(8)
		t = await reader.read(8)
		res.LogonTime = int.from_bytes(t, byteorder = 'little', signed = False) #autoalign x86
		res.LogonServer = await LSA_UNICODE_STRING.load(reader)
		res.Credentials_list_ptr = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await ULONG.loadvalue(reader)
		await reader.align()
		res.CredentialManager = await PVOID.load(reader)
		return res

class PKIWI_MSV1_0_LIST_62(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_LIST_62()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_LIST_62
		return p
		
class KIWI_MSV1_0_LIST_62:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.hSemaphore6 = None
		self.unk7 = None
		self.hSemaphore8 = None
		self.unk9 = None
		self.unk10 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.LocallyUniqueIdentifier = None
		self.SecondaryLocallyUniqueIdentifier = None
		self.UserName = None
		self.Domaine = None
		self.unk14 = None
		self.unk15 = None
		self.Type = None
		self.pSid = None
		self.LogonType = None
		self.unk18 = None
		self.Session = None
		self.LogonTime = None
		self.LogonServer = None
		self.Credentials_list_ptr = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.unk24 = None
		self.unk25 = None
		self.unk26 = None
		self.unk27 = None
		self.unk28 = None
		self.unk29 = None
		self.CredentialManager = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_LIST_62()
		res.Flink = await PKIWI_MSV1_0_LIST_62.load(reader)
		res.Blink = await PKIWI_MSV1_0_LIST_62.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await PVOID.loadvalue(reader)
		res.unk3 = await ULONG.loadvalue(reader)
		res.unk4 = await ULONG.loadvalue(reader)
		res.unk5 = await ULONG.loadvalue(reader)
		await reader.align()
		res.hSemaphore6 = await HANDLE.loadvalue(reader)
		res.unk7 = await PVOID.loadvalue(reader)
		res.hSemaphore8 = await HANDLE.loadvalue(reader)
		res.unk9 = await PVOID.loadvalue(reader)
		res.unk10 = await PVOID.loadvalue(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		res.unk12 = await ULONG.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.SecondaryLocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine = await LSA_UNICODE_STRING.load(reader)
		res.unk14 = await PVOID.loadvalue(reader)
		res.unk15 = await PVOID.loadvalue(reader)
		res.Type = await LSA_UNICODE_STRING.load(reader)
		res.pSid = await PSID.load(reader)
		res.LogonType = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk18 = await PVOID.loadvalue(reader)
		res.Session = await ULONG.loadvalue(reader)
		await reader.align()
		t = await reader.read(8)
		res.LogonTime = int.from_bytes(t, byteorder = 'little', signed = False) #autoalign x86
		res.LogonServer = await LSA_UNICODE_STRING.load(reader)
		res.Credentials_list_ptr = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await ULONG.loadvalue(reader)
		res.unk23 = await ULONG.loadvalue(reader)
		res.unk24 = await ULONG.loadvalue(reader)
		res.unk25 = await ULONG.loadvalue(reader)
		res.unk26 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk27 = await PVOID.loadvalue(reader)
		res.unk28 = await PVOID.loadvalue(reader)
		res.unk29 = await PVOID.loadvalue(reader)
		res.CredentialManager = await PVOID.load(reader)
		return res
		
class PKIWI_MSV1_0_LIST_63(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_MSV1_0_LIST_63()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_MSV1_0_LIST_63
		return p
		
class KIWI_MSV1_0_LIST_63:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.hSemaphore6 = None
		self.unk7 = None
		self.hSemaphore8 = None
		self.unk9  = None
		self.unk10 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.LocallyUniqueIdentifier = None
		self.SecondaryLocallyUniqueIdentifier = None
		self.waza = None
		self.UserName = None
		self.Domaine = None
		self.unk14 = None
		self.unk15 = None
		self.Type = None
		self.pSid = None
		self.LogonType = None
		self.unk18 = None
		self.Session = None
		self.LogonTime =  None
		self.LogonServer = None
		self.Credentials_list_ptr = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.unk24 = None
		self.unk25 = None
		self.unk26 = None
		self.unk27 = None
		self.unk28 = None
		self.unk29 = None
		self.CredentialManager = None

	@staticmethod
	async def load(reader):
		res = KIWI_MSV1_0_LIST_63()
		res.Flink = await PKIWI_MSV1_0_LIST_63.load(reader)
		res.Blink = await PKIWI_MSV1_0_LIST_63.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await PVOID.loadvalue(reader)
		res.unk3 = await ULONG.loadvalue(reader)
		res.unk4 = await ULONG.loadvalue(reader)
		res.unk5 = await ULONG.loadvalue(reader)
		await reader.align()
		res.hSemaphore6 = await HANDLE.loadvalue(reader)
		res.unk7 = await PVOID.loadvalue(reader)
		res.hSemaphore8 = await HANDLE.loadvalue(reader)
		res.unk9 = await PVOID.loadvalue(reader)
		res.unk10 = await PVOID.loadvalue(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		res.unk12 = await ULONG.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		await reader.align()
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.SecondaryLocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.waza = await reader.read(12)
		await reader.align()
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine = await LSA_UNICODE_STRING.load(reader)
		res.unk14 = await PVOID.loadvalue(reader)
		res.unk15 = await PVOID.loadvalue(reader)
		res.Type = await LSA_UNICODE_STRING.load(reader)
		res.pSid = await PSID.load(reader)
		res.LogonType = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk18 = await PVOID.loadvalue(reader)
		res.Session = await ULONG.loadvalue(reader)
		await reader.align(8)
		t = await reader.read(8)
		res.LogonTime =  int.from_bytes(t, byteorder = 'little', signed = False) #autoalign x86
		res.LogonServer = await LSA_UNICODE_STRING.load(reader)
		res.Credentials_list_ptr = await PKIWI_MSV1_0_CREDENTIAL_LIST.load(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await ULONG.loadvalue(reader)
		res.unk23 = await ULONG.loadvalue(reader)
		res.unk24 = await ULONG.loadvalue(reader)
		res.unk25 = await ULONG.loadvalue(reader)
		res.unk26 = await ULONG.loadvalue(reader)
		await reader.align()
		#input('CredentialManager\n' + hexdump(reader.peek(0x100)))
		res.unk27 = await PVOID.loadvalue(reader)
		res.unk28 = await PVOID.loadvalue(reader)
		res.unk29 = await PVOID.loadvalue(reader)
		res.CredentialManager = await PVOID.load(reader)
		return res