#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from pypykatz.alsadecryptor.win_datatypes import POINTER, PVOID, ULONG, LIST_ENTRY, \
	DWORD, LSA_UNICODE_STRING, PKERB_EXTERNAL_NAME, KIWI_GENERIC_PRIMARY_CREDENTIAL, \
	LUID, PLSAISO_DATA_BLOB, ULONG64, FILETIME, PCWSTR, SIZE_T, BOOL
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class KerberosTemplate(PackageTemplate):
	def __init__(self, sysinfo):
		super().__init__('Kerberos', sysinfo)
		self.signature = None
		self.first_entry_offset = None
		self.kerberos_session_struct = None
		self.kerberos_ticket_struct = None
		self.keys_list_struct = None
		self.hash_password_struct = None
		self.csp_info_struct = None
		
	@staticmethod
	def get_template(sysinfo):
		#input('%s %s' % (sysinfo.architecture,sysinfo.buildnumber))
		template = KerberosTemplate(sysinfo)
		if sysinfo.architecture == KatzSystemArchitecture.X64:		
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x48\x3b\xfe\x0f\x84'
				template.first_entry_offset = -4
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_51
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_51
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_5
				template.hash_password_struct = KERB_HASHPASSWORD_5
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_5
				
				
			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x48\x3b\xfe\x0f\x84'
				template.first_entry_offset = -4
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_52
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_5
				template.hash_password_struct = KERB_HASHPASSWORD_5
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_5
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_60
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_60
				
			elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_6
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_60
			
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_6
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_62
				
			elif WindowsBuild.WIN_10_1507.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1511.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_10
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_6
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
				
			elif WindowsBuild.WIN_10_1511.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_10
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_10
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
				

			elif WindowsBuild.WIN_10_1607.value <= sysinfo.buildnumber < WindowsBuild.WIN_11_2022.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_10_1607
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_10_1607
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6_1607
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
			
			elif WindowsBuild.WIN_11_2022.value <= sysinfo.buildnumber < WindowsBuild.WIN_11_24H2.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_10_1607
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_11
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6_1607
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
			
			elif sysinfo.buildnumber >= WindowsBuild.WIN_11_24H2.value:
				template.signature = b'\x48\x8b\x18\x48\x8d\x0d'
				template.first_entry_offset = 6
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_24H2
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_11
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6_1607
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
			
			else:
				raise Exception('Could not identify template! Architecture: %s sysinfo.buildnumber: %s' % (sysinfo.architecture, sysinfo.buildnumber))
			
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x8B\x7D\x08\x8B\x17\x39\x50'
				template.first_entry_offset = -8
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_51
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_51
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_5
				template.hash_password_struct = KERB_HASHPASSWORD_5
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_5
				
				
			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x8B\x7D\x08\x8B\x17\x39\x50'
				template.first_entry_offset = -8
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_52
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_5
				template.hash_password_struct = KERB_HASHPASSWORD_5
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_5
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.signature = b'\x53\x8b\x18\x50\x56'
				template.first_entry_offset = -11
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_60
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_60
				
			elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x53\x8b\x18\x50\x56'
				template.first_entry_offset = -11
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_6
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_60
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsBuild.WIN_BLUE.value:
				template.signature = b'\x57\x8b\x38\x50\x68'
				template.first_entry_offset = -14
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_6
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_62
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x56\x8b\x30\x50\x57'
				template.first_entry_offset = -15
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_6
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_62
			
			####DOUBLE CHECK THE STRUCTURES BELOW THIS LINE!!!!
			#### kerbHelper[N] -> KerberosReferences... {-15,7}}, here N= 7
			
			elif WindowsBuild.WIN_10_1507.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1511.value:
				template.signature = b'\x56\x8b\x30\x50\x57'
				template.first_entry_offset = -15
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_10_X86
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_6
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
				
				
			elif WindowsBuild.WIN_10_1511.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1903.value:
				template.signature = b'\x56\x8b\x30\x50\x57'
				template.first_entry_offset = -15
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_10_1607_X86
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_10_1607
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6_1607
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
				
				
			elif WindowsBuild.WIN_10_1903.value <= sysinfo.buildnumber:
				template.signature = b'\x56\x8b\x30\x50\x53'
				template.first_entry_offset = -15
				template.kerberos_session_struct = KIWI_KERBEROS_LOGON_SESSION_10_1607_X86
				template.kerberos_ticket_struct = KIWI_KERBEROS_INTERNAL_TICKET_10_1607
				template.keys_list_struct = KIWI_KERBEROS_KEYS_LIST_6
				template.hash_password_struct = KERB_HASHPASSWORD_6_1607
				template.csp_info_struct = KIWI_KERBEROS_CSP_INFOS_10
		
		
		else:
			raise Exception('Unknown architecture! %s' % sysinfo.architecture)

			
		return template
		
class PKERB_SMARTCARD_CSP_INFO_5(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKERB_SMARTCARD_CSP_INFO_5()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KERB_SMARTCARD_CSP_INFO_5
		return p
		

class KERB_SMARTCARD_CSP_INFO_5:
	def __init__(self):
		#self.dwCspInfoLen = DWORD(reader).value
		self.ContextInformation = None
		self.nCardNameOffset = None
		self.nReaderNameOffset = None
		self.nContainerNameOffset = None
		self.nCSPNameOffset = None
		self.bBuffer = None


	@staticmethod
	async def load(reader, size):
		res = KERB_SMARTCARD_CSP_INFO_5()
		pos = reader.tell()
		#self.dwCspInfoLen = DWORD(reader).value
		res.ContextInformation = await PVOID.loadvalue(reader)
		res.nCardNameOffset = await ULONG.loadvalue(reader)
		res.nReaderNameOffset = await ULONG.loadvalue(reader)
		res.nContainerNameOffset = await ULONG.loadvalue(reader)
		res.nCSPNameOffset = await ULONG.loadvalue(reader)
		diff = reader.tell() - pos
		data = await reader.read(size - diff + 4)
		res.bBuffer = io.BytesIO(data)
		return res

	def read_wcharnull(self, buffer, tpos):
		pos = buffer.tell()
		buffer.seek(tpos, 0)
		data = b''
		i=0
		nc = 0
		while i < 255:
			if nc == 3:
				break
			c = buffer.read(1)
			if c == b'\x00':
				nc += 1
			else:
				nc = 0
			data += c
			i += 1
		buffer.seek(pos, 0)
		return data.decode('utf-16-le').replace('\x00', '')

	def get_infos(self):
		t = {}
		t['CardName'] = self.read_wcharnull(self.bBuffer, self.nCardNameOffset)
		t['ReaderName'] = self.read_wcharnull(self.bBuffer, self.nReaderNameOffset)
		t['ContainerName'] = self.read_wcharnull(self.bBuffer, self.nContainerNameOffset)
		t['CSPName'] = self.read_wcharnull(self.bBuffer, self.nCSPNameOffset)

		return t

class PKERB_SMARTCARD_CSP_INFO(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKERB_SMARTCARD_CSP_INFO()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KERB_SMARTCARD_CSP_INFO
		return p
		
		
class KERB_SMARTCARD_CSP_INFO:
	def __init__(self):
		self.MessageType = None
		self.ContextInformation = None
		self.SpaceHolderForWow64 = None
		self.flags = None
		self.KeySpec = None
		self.nCardNameOffset = None
		self.nReaderNameOffset = None
		self.nContainerNameOffset = None
		self.nCSPNameOffset = None
		self.bBuffer = None
	
	@staticmethod
	async def load(reader, size):
		res = KERB_SMARTCARD_CSP_INFO()
		pos = reader.tell()
		#self.dwCspInfoLen = DWORD(reader).value
		res.MessageType = await DWORD.loadvalue(reader).value
		res.ContextInformation = await PVOID.loadvalue(reader).value
		res.SpaceHolderForWow64 = await ULONG64.loadvalue(reader).value
		res.flags = await DWORD.loadvalue(reader).value
		res.KeySpec = await DWORD.loadvalue(reader).value
		res.nCardNameOffset = await ULONG.loadvalue(reader).value
		res.nCardNameOffset *= 2
		res.nReaderNameOffset = await ULONG.loadvalue(reader).value
		res.nReaderNameOffset *= 2
		res.nContainerNameOffset = await ULONG.loadvalue(reader).value
		res.nContainerNameOffset *= 2
		res.nCSPNameOffset = await ULONG.loadvalue(reader).value
		res.nCSPNameOffset *= 2
		diff = reader.tell() - pos
		data = await reader.read(size - diff + 4)
		res.bBuffer = io.BytesIO(data)
		return res

	def read_wcharnull(self, buffer, tpos):
		pos = buffer.tell()
		buffer.seek(tpos, 0)
		data = b''
		i=0
		nc = 0
		while i < 255:
			if nc == 3:
				break
			c = buffer.read(1)
			if c == b'\x00':
				nc += 1
			else:
				nc = 0
			data += c
			i += 1
		buffer.seek(pos, 0)
		return data.decode('utf-16-le').replace('\x00', '')

	def get_infos(self):
		t = {}
		t['CardName'] = self.read_wcharnull(self.bBuffer, self.nCardNameOffset)
		t['ReaderName'] = self.read_wcharnull(self.bBuffer, self.nReaderNameOffset)
		t['ContainerName'] = self.read_wcharnull(self.bBuffer, self.nContainerNameOffset)
		t['CSPName'] = self.read_wcharnull(self.bBuffer, self.nCSPNameOffset)

		return t
		
class PKIWI_KERBEROS_CSP_INFOS_5(POINTER):	
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_CSP_INFOS_5()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_CSP_INFOS_5
		return p

class KIWI_KERBEROS_CSP_INFOS_5:
	def __init__(self):	
		self.PinCode = None
		self.unk0 = None
		self.unk1 = None
		self.CertificateInfos = None
		self.unkData = None
		self.Flags = None
		self.CspDataLength = None
		self.CspData = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_CSP_INFOS_5()
		res.PinCode = await LSA_UNICODE_STRING.load(reader)
		res.unk0 = await PVOID.load(reader)
		res.unk1 = await PVOID.load(reader)
		res.CertificateInfos = await PVOID.load(reader)
		res.unkData = await PVOID.load(reader)                      #	// 0 = CspData
		res.Flags = await DWORD.loadvalue(reader)                  #	// 1 = CspData (not 0x21)(reader).value
		res.CspDataLength = await DWORD.loadvalue(reader)
		res.CspData = await KERB_SMARTCARD_CSP_INFO_5.load(reader, size = res.CspDataLength)
		return res

	 
class PKIWI_KERBEROS_CSP_INFOS_60(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_CSP_INFOS_60()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_CSP_INFOS_60
		return p


class KIWI_KERBEROS_CSP_INFOS_60:
	def __init__(self):
		self.PinCode = None
		self.unk0 = None
		self.unk1 = None
		self.CertificateInfos = None
		self.unkData = None
		self.Flags = None
		self.unkFlags = None
		self.CspDataLength = None
		self.CspData = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_CSP_INFOS_5()
		res.PinCode = await LSA_UNICODE_STRING.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.CertificateInfos = await PVOID.loadvalue(reader)
		res.unkData = await PVOID.loadvalue(reader)           #	// 0 = CspData
		res.Flags    = await DWORD.loadvalue(reader)	            #// 0 = CspData(reader).value
		res.unkFlags = await DWORD.loadvalue(reader)      	#// 0x141(reader).value
		res.CspDataLength = await DWORD.loadvalue(reader)
		res.CspData = await KERB_SMARTCARD_CSP_INFO.load(reader, size = res.CspDataLength)
		return res

class PKIWI_KERBEROS_CSP_INFOS_62(POINTER):	
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_CSP_INFOS_62()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_CSP_INFOS_62
		return p

	 
class KIWI_KERBEROS_CSP_INFOS_62:
	def __init__(self):
		self.PinCode = None
		self.unk0 = None
		self.unk1 = None
		self.CertificateInfos = None
		self.unk2 = None
		self.unkData = None
		self.Flags = None
		self.unkFlags = None
		self.CspDataLength = None
		self.CspData = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_CSP_INFOS_62()
		res.PinCode = await LSA_UNICODE_STRING.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.CertificateInfos = await PVOID.loadvalue(reader)
		res.unk2     = await PVOID.loadvalue(reader)
		res.unkData  = await PVOID.loadvalue(reader)	          #// 0 = CspData(reader).value
		res.Flags    = await DWORD.loadvalue(reader)	             #// 0 = CspData(reader).value
		res.unkFlags = await DWORD.loadvalue(reader)	            #// 0x141 (not 0x61)
		res.CspDataLength = await DWORD.loadvalue(reader)
		res.CspData = await KERB_SMARTCARD_CSP_INFO.load(reader, size = res.CspDataLength)
		return res

		
class PKIWI_KERBEROS_CSP_INFOS_10(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_CSP_INFOS_10()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_CSP_INFOS_10
		return p

class KIWI_KERBEROS_CSP_INFOS_10:
	def __init__(self):
		self.PinCode = None
		self.unk0 = None
		self.unk1 = None
		self.CertificateInfos = None
		self.unk2 = None
		self.unkData = None
		self.Flags = None
		self.unkFlags = None
		self.unk3 = None
		self.CspDataLength = None
		self.CspData = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_CSP_INFOS_10()
		res.PinCode = await LSA_UNICODE_STRING.load(reader)
		res.unk0    = await PVOID.loadvalue(reader)
		res.unk1    = await PVOID.loadvalue(reader)
		res.CertificateInfos = await PVOID.loadvalue(reader)
		res.unk2     = await PVOID.loadvalue(reader)
		res.unkData  = await PVOID.loadvalue(reader)	        #// 0 = CspData
		res.Flags    = await DWORD.loadvalue(reader)	            #// 0 = CspData(reader).value
		res.unkFlags = await DWORD.loadvalue(reader)	        #// 0x141 (not 0x61)(reader).value
		res.unk3     = await PVOID.loadvalue(reader)
		res.CspDataLength = await DWORD.loadvalue(reader)
		res.CspData = await KERB_SMARTCARD_CSP_INFO.load(reader, size = res.CspDataLength)
		return res

class PKIWI_KERBEROS_LOGON_SESSION_51(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_LOGON_SESSION_51()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_LOGON_SESSION_51
		return p

class KIWI_KERBEROS_LOGON_SESSION_51:
	def __init__(self):
		self.UsageCount = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None      #	// filetime.1 ?
		self.unk4 = None    	#// filetime.2 ?(reader).value
		self.unk5 = None
		self.unk6 = None
		self.unk7 = None
		self.LocallyUniqueIdentifier = None
		#self.unkAlign = ULONG(reader).value  #aliing on x86(reader).value
		self.unk8 = None
		self.unk9 = None
		self.unk10 = None     #	// filetime.1 ?(reader).value
		self.unk11 = None     #	// filetime.2 ?(reader).value
		self.unk12 = None
		self.unk13 = None
		self.unk14 = None
		self.credentials = None
		self.unk15 = None
		self.unk16 = None
		self.unk17 = None
		self.unk18 = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.pKeyList = None
		self.unk24 = None
		self.Tickets_1 = None
		self.Tickets_2 = None
		self.Tickets_3 = None
		self.SmartcardInfos = None
	
	@staticmethod
	async def load(reader):
		#IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		res = KIWI_KERBEROS_LOGON_SESSION_51()
		res.UsageCount = await ULONG.loadvalue(reader)
		res.unk0 = await LIST_ENTRY.load(reader)
		res.unk1 = await LIST_ENTRY.load(reader)
		res.unk2 = await PVOID.loadvalue(reader)
		res.unk3 = await ULONG.loadvalue(reader)      #	// filetime.1 ?
		res.unk4 = await ULONG.loadvalue(reader)    	#// filetime.2 ?(reader).value
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.unk7 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		await reader.align(8)
		#self.unkAlign = ULONG(reader).value  #aliing on x86(reader).value
		res.unk8  = await FILETIME.loadvalue(reader)
		res.unk9  = await PVOID.loadvalue(reader)
		res.unk10 = await ULONG.loadvalue(reader)     #	// filetime.1 ?(reader).value
		res.unk11 = await ULONG.loadvalue(reader)     #	// filetime.2 ?(reader).value
		res.unk12 = await PVOID.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		res.unk14 = await PVOID.loadvalue(reader)
		res.credentials = await KIWI_GENERIC_PRIMARY_CREDENTIAL.load(reader)
		res.unk15 = await ULONG.loadvalue(reader)
		res.unk16 = await ULONG.loadvalue(reader)
		res.unk17 = await ULONG.loadvalue(reader)
		res.unk18 = await ULONG.loadvalue(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.pKeyList = await PVOID.load(reader)
		res.unk24 = await PVOID.loadvalue(reader)
		res.Tickets_1 = await LIST_ENTRY.load(reader)
		res.Tickets_2 = await LIST_ENTRY.load(reader)
		res.Tickets_3 = await LIST_ENTRY.load(reader)
		res.SmartcardInfos = await PVOID.load(reader)
		return res

		
class PKIWI_KERBEROS_LOGON_SESSION(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_LOGON_SESSION()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_LOGON_SESSION
		return p

class KIWI_KERBEROS_LOGON_SESSION:
	def __init__(self):
		self.UsageCount = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None     #	// filetime.1 ?
		self.unk3 = None	   #// filetime.2 ?(reader).value
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.LocallyUniqueIdentifier = None
		#self.unkAlign = ULONG(reader).value#ifdef _M_IX86(reader).value
		self.unk7  = None
		self.unk8  = None
		self.unk9  = None      #	// filetime.1 ?(reader).value
		self.unk10 = None     #	// filetime.2 ?(reader).value
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.credentials = None
		self.unk14 = None
		self.unk15 = None
		self.unk16 = None
		self.unk17 = None
		self.unk18 = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.pKeyList = None
		self.unk23 = None
		self.Tickets_1 = None
		self.unk24 = None
		self.Tickets_2 = None
		self.unk25 = None
		self.Tickets_3 = None
		self.unk26 = None
		self.SmartcardInfos = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_LOGON_SESSION()
		res.UsageCount = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk0 = await LIST_ENTRY.load(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.unk2 = await ULONG.loadvalue(reader)     #	// filetime.1 ?
		res.unk3 = await ULONG.loadvalue(reader)	   #// filetime.2 ?(reader).value
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		#self.unkAlign = ULONG(reader).value#ifdef _M_IX86(reader).value
		await reader.align(8)
		res.unk7  = await FILETIME.loadvalue(reader)
		res.unk8  = await PVOID.loadvalue(reader)
		res.unk9  = await ULONG.loadvalue(reader)      #	// filetime.1 ?(reader).value
		res.unk10 = await ULONG.loadvalue(reader)     #	// filetime.2 ?(reader).value
		res.unk11 = await PVOID.loadvalue(reader)
		res.unk12 = await PVOID.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		res.credentials = await KIWI_GENERIC_PRIMARY_CREDENTIAL.load(reader)
		res.unk14 = await ULONG.loadvalue(reader)
		res.unk15 = await ULONG.loadvalue(reader)
		res.unk16 = await ULONG.loadvalue(reader)
		res.unk17 = await ULONG.loadvalue(reader)
		res.unk18 = await PVOID.loadvalue(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.pKeyList = await PVOID.load(reader)
		res.unk23 = await PVOID.loadvalue(reader)
		await reader.align()
		res.Tickets_1 = await LIST_ENTRY.load(reader)
		res.unk24     = await FILETIME.loadvalue(reader)
		res.Tickets_2 = await LIST_ENTRY.load(reader)
		res.unk25     = await FILETIME.loadvalue(reader)
		res.Tickets_3 = await LIST_ENTRY.load(reader)
		res.unk26     = await FILETIME.loadvalue(reader)
		res.SmartcardInfos = await PVOID.load(reader)
		return res

class PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_10_PRIMARY_CREDENTIAL
		return p
		
class KIWI_KERBEROS_10_PRIMARY_CREDENTIAL:
	def __init__(self):
		self.UserName = None
		self.Domaine = None
		self.unk0 = None
		self.Password = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_10_PRIMARY_CREDENTIAL()
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine  = await LSA_UNICODE_STRING.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.Password = await LSA_UNICODE_STRING.load(reader)
		return res

class PKIWI_KERBEROS_LOGON_SESSION_10(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_LOGON_SESSION_10()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_LOGON_SESSION_10
		return p
		
class KIWI_KERBEROS_LOGON_SESSION_10_X86:
	def __init__(self):	
		self.UsageCount = None
		self.unk0 = None
		self.unk1 = None
		self.unk1b = None
		self.unk2 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.LocallyUniqueIdentifier = None
		self.unk7 = None
		self.unk8 = None
		self.unk8b = None
		self.unk9 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.credentials = None
		self.unk14 = None
		self.unk15 = None
		self.unk16 = None
		self.unk17 = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.unk24 = None
		self.unk25 = None
		self.pKeyList = None
		self.unk26 = None
		self.Tickets_1 = None
		self.unk27 = None
		self.Tickets_2 = None
		self.unk28 = None
		self.Tickets_3 = None
		self.unk29 = None
		self.SmartcardInfos = None
	

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_LOGON_SESSION_10_X86()
		res.UsageCount = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk0  = await LIST_ENTRY.load(reader)
		res.unk1  = await PVOID.loadvalue(reader)
		res.unk1b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await FILETIME.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		#print(hex(self.LocallyUniqueIdentifier))
		#input('unk7\n' + hexdump(reader.peek(0x100)))
		await reader.align()
		res.unk7  = await FILETIME.loadvalue(reader)
		res.unk8  = await PVOID.loadvalue(reader)
		res.unk8b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk9  = await FILETIME.loadvalue(reader)
		res.unk11 = await PVOID.loadvalue(reader)
		res.unk12 = await PVOID.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		await reader.align(8)
		
		#input('credentials\n' + hexdump(reader.peek(0x100)))
		res.credentials = await KIWI_KERBEROS_10_PRIMARY_CREDENTIAL.load(reader)
		res.unk14 = await ULONG.loadvalue(reader)
		res.unk15 = await ULONG.loadvalue(reader)
		res.unk16 = await ULONG.loadvalue(reader)
		res.unk17 = await ULONG.loadvalue(reader)
		#//PVOID		unk18 = (reader).value
		await reader.align(8)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.unk23 = await PVOID.loadvalue(reader)
		res.unk24 = await PVOID.loadvalue(reader)
		res.unk25 = await PVOID.loadvalue(reader)
		res.pKeyList = await PVOID.load(reader)
		res.unk26 = await PVOID.loadvalue(reader)
		#input('pKeyList\n' + hexdump(reader.peek(0x100)))
		await reader.align()
		#input('Tickets_1\n' + hexdump(reader.peek(0x100)))
		res.Tickets_1 = await LIST_ENTRY.load(reader)
		res.unk27 = await FILETIME.loadvalue(reader)
		res.Tickets_2 = await LIST_ENTRY.load(reader)
		res.unk28 = await FILETIME.loadvalue(reader)
		res.Tickets_3 = await LIST_ENTRY.load(reader)
		res.unk29 = await FILETIME.loadvalue(reader)
		res.SmartcardInfos = await PVOID.load(reader)
		return res
		
class KIWI_KERBEROS_LOGON_SESSION_10:
	def __init__(self):	
		self.UsageCount = None
		self.unk0 = None
		self.unk1 = None
		self.unk1b = None
		self.unk2 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.LocallyUniqueIdentifier = None
		self.unk7 = None
		self.unk8 = None
		self.unk8b = None
		self.unk9 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None		
		self.credentials = None
		self.unk14 = None
		self.unk15 = None
		self.unk16 = None
		self.unk17 = None
		#self.unk18 = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.unk24 = None
		self.unk25 = None
		self.pKeyList = None
		self.unk26 = None
		self.Tickets_1 = None
		self.unk27 = None
		self.Tickets_2 = None
		self.unk28 = None
		self.Tickets_3 = None
		self.unk29 = None
		self.SmartcardInfos = None

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_LOGON_SESSION_10()
		res.UsageCount = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk0  = await LIST_ENTRY.load(reader)
		res.unk1  = await PVOID.loadvalue(reader)
		res.unk1b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await FILETIME.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.unk7  = await FILETIME.loadvalue(reader)
		res.unk8  = await PVOID.loadvalue(reader)
		res.unk8b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk9  = await FILETIME.loadvalue(reader)
		res.unk11 = await PVOID.loadvalue(reader)
		res.unk12 = await PVOID.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)		
		res.credentials = await KIWI_KERBEROS_10_PRIMARY_CREDENTIAL.load(reader)
		res.unk14 = await ULONG.loadvalue(reader)
		res.unk15 = await ULONG.loadvalue(reader)
		res.unk16 = await ULONG.loadvalue(reader)
		res.unk17 = await ULONG.loadvalue(reader)
		#self.unk18 = PVOID(reader).value
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.unk23 = await PVOID.loadvalue(reader)
		res.unk24 = await PVOID.loadvalue(reader)
		res.unk25 = await PVOID.loadvalue(reader)
		res.pKeyList = await PVOID.load(reader)
		res.unk26 = await PVOID.loadvalue(reader)
		res.Tickets_1 = await LIST_ENTRY.load(reader)
		res.unk27 = await FILETIME.loadvalue(reader)
		res.Tickets_2 = await LIST_ENTRY.load(reader)
		res.unk28 = await FILETIME.loadvalue(reader)
		res.Tickets_3 = await LIST_ENTRY.load(reader)
		res.unk29 = await FILETIME.loadvalue(reader)
		res.SmartcardInfos = await PVOID.load(reader)
		return res

class PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO
		return p

class KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO:
	def __init__(self):
		self.StructSize = None
		self.isoBlob    = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO()
		res.StructSize = await DWORD.loadvalue(reader)
		await reader.align()
		res.isoBlob    = await PLSAISO_DATA_BLOB.load(reader)  #POINTER!!!! #// aligned =
		return res

class PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607(POINTER):	
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607
		return p
		
class KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607:
	def __init__(self):
		self.UserName = None
		self.Domaine = None
		self.unkFunction = None
		self.type = None
		self.Password = None
		self.IsoPassword = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607()
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine  = await LSA_UNICODE_STRING.load(reader)
		res.unkFunction = await PVOID.loadvalue(reader)
		res.type = await DWORD.loadvalue(reader) # // or flags 2 = normal, 1 = ISO(reader).value
		await reader.align()
		res.Password    = await LSA_UNICODE_STRING.load(reader) #	union {
		res.IsoPassword = await KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO.load(reader)
		return res

class PKIWI_KERBEROS_LOGON_SESSION_10_1607(POINTER):	
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_LOGON_SESSION_10_1607()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_LOGON_SESSION_10_1607
		return p

		
class KIWI_KERBEROS_LOGON_SESSION_10_1607:
	def __init__(self):
		self.UsageCount = None
		self.unk0 = None
		self.unk1 = None
		self.unk1b = None
		self.unk2 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.LocallyUniqueIdentifier = None
		self.unk7 = None
		self.unk8 = None
		self.unk8b = None
		self.unk9 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.credentials = None
		self.unk14 = None
		self.unk15 = None
		self.unk16 = None
		self.unk17 = None
		self.unk18 = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.pKeyList = None
		self.unk26 = None
		self.Tickets_1 = None
		self.unk27 = None
		self.Tickets_2 = None
		self.unk28 = None
		self.Tickets_3 = None
		self.unk29 = None
		self.SmartcardInfos = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_LOGON_SESSION_10_1607()
		res.UsageCount = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk0 = await LIST_ENTRY.load(reader)
		res.unk1  = await PVOID.loadvalue(reader)
		res.unk1b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await FILETIME.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.unk7  = await FILETIME.loadvalue(reader)
		res.unk8  = await PVOID.loadvalue(reader)
		res.unk8b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk9  = await FILETIME.load(reader)
		res.unk11 = await PVOID.loadvalue(reader)
		res.unk12 = await PVOID.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		await reader.align(8)
		res.credentials = await KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607.load(reader)
		res.unk14 = await ULONG.loadvalue(reader)
		res.unk15 = await ULONG.loadvalue(reader)
		res.unk16 = await ULONG.loadvalue(reader)
		res.unk17 = await ULONG.loadvalue(reader)
		res.unk18 = await PVOID.loadvalue(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.unk23 = await PVOID.loadvalue(reader)
		#self.unk24 = PVOID(reader).value
		#self.unk25 = PVOID(reader).value
		await reader.align()
		#reader.read(8+12)
		#input('pkeylist  \n' + hexdump(reader.peek(0x50)))
		res.pKeyList = await PVOID.load(reader)
		res.unk26 = await PVOID.loadvalue(reader)
		res.Tickets_1 = await LIST_ENTRY.load(reader)
		res.unk27 = await FILETIME.loadvalue(reader)
		res.Tickets_2 = await LIST_ENTRY.load(reader)
		res.unk28 = await FILETIME.loadvalue(reader)
		res.Tickets_3 = await LIST_ENTRY.load(reader)
		res.unk29 = await FILETIME.loadvalue(reader)
		res.SmartcardInfos = await PVOID.load(reader)
		return res
		

class KIWI_KERBEROS_LOGON_SESSION_24H2:
	def __init__(self):
		self.UsageCount = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.LocallyUniqueIdentifier = None
		self.unk7 = None
		self.unk8 = None
		self.unk8b = None
		self.unk9 = None
		self.unk11 = None
		self.unk12 = None
		self.credentials = None
		self.unk14 = None
		self.unk15 = None
		self.unk16 = None
		self.unk17 = None
		self.unk18 = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.pKeyList = None
		self.unk26 = None
		self.Tickets_1 = None
		self.unk27 = None
		self.Tickets_2 = None
		self.unk28 = None
		self.Tickets_3 = None
		self.unk29 = None
		self.SmartcardInfos = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_LOGON_SESSION_24H2()
		res.UsageCount = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk0 = await LIST_ENTRY.load(reader)
		res.unk1  = await PVOID.loadvalue(reader)
		await reader.align()
		res.unk2 = await FILETIME.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.unk7  = await FILETIME.loadvalue(reader)
		res.unk8  = await PVOID.loadvalue(reader)
		res.unk8b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk9  = await FILETIME.load(reader)
		res.unk11 = await PVOID.loadvalue(reader)
		res.unk12 = await PVOID.loadvalue(reader)
		await reader.align(8)
		res.credentials = await KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607.load(reader)
		res.unk14 = await ULONG.loadvalue(reader)
		res.unk15 = await ULONG.loadvalue(reader)
		res.unk16 = await ULONG.loadvalue(reader)
		res.unk17 = await ULONG.loadvalue(reader)
		res.unk18 = await PVOID.loadvalue(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.unk23 = await PVOID.loadvalue(reader)
		await reader.align()
		res.pKeyList = await PVOID.load(reader)
		res.unk26 = await PVOID.loadvalue(reader)
		res.Tickets_1 = await LIST_ENTRY.load(reader)
		res.unk27 = await FILETIME.loadvalue(reader)
		res.Tickets_2 = await LIST_ENTRY.load(reader)
		res.unk28 = await FILETIME.loadvalue(reader)
		res.Tickets_3 = await LIST_ENTRY.load(reader)
		res.unk29 = await FILETIME.loadvalue(reader)
		res.SmartcardInfos = await PVOID.load(reader)
		return res

class KIWI_KERBEROS_LOGON_SESSION_10_1607_X86:
	def __init__(self):
		self.UsageCount = None
		self.unk0 = None
		self.unk1 = None
		self.unk1b = None
		self.unk2 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.LocallyUniqueIdentifier = None
		self.unk7 = None
		self.unk8 = None
		self.unk8b = None
		self.unk9 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.unkAlign = None
		self.credentials = None
		self.unk14 = None
		self.unk15 = None
		self.unk16 = None
		self.unk17 = None
		self.unk18 = None
		self.unk19 = None
		self.unk20 = None
		self.unk21 = None
		self.unk22 = None
		self.unk23 = None
		self.pKeyList = None
		self.unk26 = None
		self.Tickets_1 = None
		self.unk27 = None
		self.Tickets_2 = None
		self.unk28 = None
		self.Tickets_3 = None
		self.unk29 = None
		self.SmartcardInfos = None


	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_LOGON_SESSION_10_1607_X86()
		res.UsageCount = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk0 = await LIST_ENTRY.load(reader)
		res.unk1  = await PVOID.loadvalue(reader)
		res.unk1b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk2 = await FILETIME.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		#input('LocallyUniqueIdentifier\n' + hex(self.LocallyUniqueIdentifier))
		res.unk7  = await FILETIME.loadvalue(reader)
		res.unk8  = await PVOID.loadvalue(reader)
		res.unk8b = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk9  = await FILETIME.loadvalue(reader)
		res.unk11 = await PVOID.loadvalue(reader)
		res.unk12 = await PVOID.loadvalue(reader)
		res.unk13 = await PVOID.loadvalue(reader)
		res.unkAlign = await ULONG.loadvalue(reader)
		#input('credentials  \n' + hexdump(reader.peek(0x200)))
		res.credentials = await KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607.load(reader)
		res.unk14 = await ULONG.loadvalue(reader)
		res.unk15 = await ULONG.loadvalue(reader)
		res.unk16 = await ULONG.loadvalue(reader)
		res.unk17 = await ULONG.loadvalue(reader)
		res.unk18 = await PVOID.loadvalue(reader)
		res.unk19 = await PVOID.loadvalue(reader)
		res.unk20 = await PVOID.loadvalue(reader)
		res.unk21 = await PVOID.loadvalue(reader)
		res.unk22 = await PVOID.loadvalue(reader)
		res.unk23 = await PVOID.loadvalue(reader)
		#self.unk24 = PVOID(reader).value
		#self.unk25 = PVOID(reader).value
		await reader.align()
		
		res.pKeyList = await PVOID.load(reader)
		res.unk26    = await PVOID.loadvalue(reader)
		#input('Tickets_1  \n' + hexdump(reader.peek(0x200)))
		res.Tickets_1 = await LIST_ENTRY.load(reader)
		res.unk27 = await FILETIME.loadvalue(reader)
		res.Tickets_2 = await LIST_ENTRY.load(reader)
		res.unk28 = await FILETIME.loadvalue(reader)
		res.Tickets_3 = await LIST_ENTRY.load(reader)
		res.unk29 = await FILETIME.loadvalue(reader)
		res.SmartcardInfos = await PVOID.load(reader)
		return res

class PKIWI_KERBEROS_INTERNAL_TICKET_51(POINTER):	
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_INTERNAL_TICKET_51()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_INTERNAL_TICKET_51
		return p

		
class KIWI_KERBEROS_INTERNAL_TICKET_51:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.ServiceName = None
		self.TargetName = None
		self.DomainName = None
		self.TargetDomainName = None
		self.Description = None
		self.AltTargetDomainName = None
		self.ClientName = None
		self.TicketFlags = None
		self.unk2 = None
		self.KeyType = None
		self.Key = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.unk7 = None
		self.unk8 = None
		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None
		self.unk9 = None
		self.unk10 = None
		self.domain = None
		self.unk11 = None
		self.strangeNames = None
		self.unk12 = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_INTERNAL_TICKET_51()
		res.Flink = await PKIWI_KERBEROS_INTERNAL_TICKET_51.load(reader)
		res.Blink = await PKIWI_KERBEROS_INTERNAL_TICKET_51.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.ServiceName = await PKERB_EXTERNAL_NAME.load(reader)
		res.TargetName  = await PKERB_EXTERNAL_NAME.load(reader)
		res.DomainName  = await LSA_UNICODE_STRING.load(reader)
		res.TargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.Description = await LSA_UNICODE_STRING.load(reader)
		res.AltTargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.ClientName = await PKERB_EXTERNAL_NAME.load(reader)
		x = await reader.read(4)
		res.TicketFlags = int.from_bytes(x, byteorder = 'big', signed = False)
		res.unk2    = await ULONG.loadvalue(reader)
		res.KeyType = await ULONG.loadvalue(reader)
		res.Key  = await KIWI_KERBEROS_BUFFER.load(reader)
		res.unk3 = await PVOID.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.unk6 = await PVOID.loadvalue(reader)
		res.unk7 = await PVOID.loadvalue(reader)
		res.unk8 = await PVOID.loadvalue(reader)
		res.StartTime  = await FILETIME.loadvalue(reader)
		res.EndTime    = await FILETIME.loadvalue(reader)
		res.RenewUntil = await FILETIME.loadvalue(reader)
		res.unk9   = await ULONG.loadvalue(reader)
		res.unk10  = await ULONG.loadvalue(reader)
		res.domain = await PCWSTR.loadvalue(reader)
		res.unk11  = await ULONG.loadvalue(reader)
		res.strangeNames = await PVOID.loadvalue(reader)
		res.unk12 = await ULONG.loadvalue(reader)
		res.TicketEncType = await ULONG.loadvalue(reader)
		res.TicketKvno = await ULONG.loadvalue(reader)
		res.Ticket = await KIWI_KERBEROS_BUFFER.load(reader)
		return res

class PKIWI_KERBEROS_INTERNAL_TICKET_52(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_INTERNAL_TICKET_52()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_INTERNAL_TICKET_52
		return p
		

class KIWI_KERBEROS_INTERNAL_TICKET_52:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.ServiceName = None
		self.TargetName = None
		self.DomainName = None
		self.TargetDomainName = None
		self.Description = None
		self.AltTargetDomainName = None
		self.ClientName = None
		self.name0 = None
		self.TicketFlags = None
		self.unk2 = None
		self.KeyType = None
		self.Key = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None
		self.unk6 = None
		self.unk7 = None
		self.domain = None
		self.unk8 = None
		self.strangeNames = None
		self.unk9 = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None

	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_INTERNAL_TICKET_52()
		res.Flink = await PKIWI_KERBEROS_INTERNAL_TICKET_52.load(reader)
		res.Blink = await PKIWI_KERBEROS_INTERNAL_TICKET_52.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.ServiceName = await PKERB_EXTERNAL_NAME.load(reader)
		res.TargetName  = await PKERB_EXTERNAL_NAME.load(reader)
		res.DomainName  = await LSA_UNICODE_STRING.load(reader)
		res.TargetDomainName    = await LSA_UNICODE_STRING.load(reader)
		res.Description         = await LSA_UNICODE_STRING.load(reader)
		res.AltTargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.ClientName = await PKERB_EXTERNAL_NAME.load(reader)
		res.name0 = await PVOID.loadvalue(reader)
		x = await reader.read(4)
		res.TicketFlags = int.from_bytes(x, byteorder = 'big', signed = False)
		res.unk2 = await ULONG.loadvalue(reader)
		res.KeyType = await ULONG.loadvalue(reader)
		res.Key = await KIWI_KERBEROS_BUFFER.load(reader)
		res.unk3 = await PVOID.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.StartTime = await FILETIME.loadvalue(reader)
		res.EndTime   = await FILETIME.loadvalue(reader)
		res.RenewUntil= await FILETIME.loadvalue(reader)
		res.unk6 = await ULONG.loadvalue(reader)
		res.unk7 = await ULONG.loadvalue(reader)
		res.domain = await PCWSTR.loadvalue(reader)
		res.unk8 = await ULONG.loadvalue(reader)
		res.strangeNames = await PVOID.loadvalue(reader)
		res.unk9 = await ULONG.loadvalue(reader)
		res.TicketEncType = await ULONG.loadvalue(reader)
		res.TicketKvno = await ULONG.load(reader)
		res.Ticket = await KIWI_KERBEROS_BUFFER.load(reader)
		return res

class PKIWI_KERBEROS_INTERNAL_TICKET_60(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_INTERNAL_TICKET_60()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_INTERNAL_TICKET_60
		return p
		

class KIWI_KERBEROS_INTERNAL_TICKET_60:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.ServiceName = None
		self.TargetName = None
		self.DomainName = None
		self.TargetDomainName = None
		self.Description = None
		self.AltTargetDomainName = None
		self.ClientName = None
		self.name0 = None
		self.TicketFlags = None
		self.unk2 = None
		self.KeyType = None
		self.Key = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None
		self.unk6 = None
		self.unk7 = None
		self.domain = None
		self.unk8 = None
		self.strangeNames = None
		self.unk9 = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None

	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_INTERNAL_TICKET_60()
		res.Flink = await PKIWI_KERBEROS_INTERNAL_TICKET_60.load(reader)
		res.Blink = await PKIWI_KERBEROS_INTERNAL_TICKET_60.load(reader)
		res.unk0  = await PVOID.loadvalue(reader)
		res.unk1  = await PVOID.loadvalue(reader)
		res.ServiceName = await PKERB_EXTERNAL_NAME.load(reader)
		res.TargetName  = await PKERB_EXTERNAL_NAME.load(reader)
		res.DomainName  = await LSA_UNICODE_STRING.load(reader)
		res.TargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.Description = await LSA_UNICODE_STRING.load(reader)
		res.AltTargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.ClientName = await PKERB_EXTERNAL_NAME.load(reader)
		res.name0 = await PVOID.loadvalue(reader)
		x = await reader.read(4)
		res.TicketFlags = int.from_bytes(x, byteorder = 'big', signed = False)
		res.unk2    = await ULONG.loadvalue(reader)
		res.KeyType = await ULONG.loadvalue(reader)
		res.Key  = await KIWI_KERBEROS_BUFFER.load(reader)
		res.unk3 = await PVOID.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.StartTime  = await FILETIME.loadvalue(reader)
		res.EndTime    = await FILETIME.loadvalue(reader)
		res.RenewUntil = await FILETIME.loadvalue(reader)
		res.unk6 = await ULONG.loadvalue(reader)
		res.unk7 = await ULONG.loadvalue(reader)
		res.domain = await PCWSTR.loadvalue(reader)
		res.unk8   = await ULONG.loadvalue(reader)
		res.strangeNames = await PVOID.loadvalue(reader)
		res.unk9          = await ULONG.loadvalue(reader)
		res.TicketEncType = await ULONG.loadvalue(reader)
		res.TicketKvno    = await ULONG.loadvalue(reader)
		res.Ticket = await KIWI_KERBEROS_BUFFER.load(reader)
		return res

class PKIWI_KERBEROS_INTERNAL_TICKET_6(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_INTERNAL_TICKET_6()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_INTERNAL_TICKET_6
		return p
		
class KIWI_KERBEROS_INTERNAL_TICKET_6:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.ServiceName = None
		self.TargetName = None
		self.DomainName = None
		self.TargetDomainName = None
		self.Description = None
		self.AltTargetDomainName = None
		self.KDCServer = None
		self.ClientName = None
		self.name0 = None
		self.TicketFlags = None
		self.unk2 = None
		self.KeyType = None
		self.Key = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None
		self.unk6 = None
		self.unk7 = None
		self.domain = None
		self.unk8 = None
		self.strangeNames = None
		self.unk9 = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_INTERNAL_TICKET_6()
		res.Flink = await PKIWI_KERBEROS_INTERNAL_TICKET_6.load(reader)
		res.Blink = await PKIWI_KERBEROS_INTERNAL_TICKET_6.load(reader)
		res.unk0  = await PVOID.loadvalue(reader)
		res.unk1  = await PVOID.loadvalue(reader)
		res.ServiceName = await PKERB_EXTERNAL_NAME.load(reader)
		res.TargetName =  await PKERB_EXTERNAL_NAME.load(reader)
		res.DomainName =  await LSA_UNICODE_STRING.load(reader)
		res.TargetDomainName    = await LSA_UNICODE_STRING.load(reader)
		res.Description         = await LSA_UNICODE_STRING.load(reader)
		res.AltTargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.KDCServer           = await LSA_UNICODE_STRING.load(reader) #	//?(reader).value
		res.ClientName          = await PKERB_EXTERNAL_NAME.load(reader)
		res.name0 = await PVOID.loadvalue(reader)
		x = await reader.read(4)
		res.TicketFlags = int.from_bytes(x, byteorder = 'big', signed = False)#ULONG(reader).value
		res.unk2    = await ULONG.loadvalue(reader)
		res.KeyType = await ULONG.loadvalue(reader)
		await reader.align()
		res.Key  = await KIWI_KERBEROS_BUFFER.load(reader)
		res.unk3 = await PVOID.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		res.StartTime  = await FILETIME.loadvalue(reader)
		res.EndTime    = await FILETIME.loadvalue(reader)
		res.RenewUntil = await FILETIME.loadvalue(reader)
		res.unk6 = await ULONG.loadvalue(reader)
		res.unk7 = await ULONG.loadvalue(reader)
		res.domain = await PCWSTR.loadvalue(reader)
		res.unk8 = await ULONG.loadvalue(reader)
		await reader.align()
		res.strangeNames = await PVOID.loadvalue(reader)
		res.unk9          = await ULONG.loadvalue(reader)
		res.TicketEncType = await ULONG.loadvalue(reader)
		res.TicketKvno    = await ULONG.loadvalue(reader)
		await reader.align()
		res.Ticket = await KIWI_KERBEROS_BUFFER.load(reader)
		return res

class PKIWI_KERBEROS_INTERNAL_TICKET_10(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_INTERNAL_TICKET_10()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_INTERNAL_TICKET_10
		return p
		
class KIWI_KERBEROS_INTERNAL_TICKET_10:
	def __init__(self):
		#input('KIWI_KERBEROS_INTERNAL_TICKET_10\n' + hexdump(reader.peek(0x100)))
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.ServiceName = None
		self.TargetName = None
		self.DomainName = None
		self.TargetDomainName = None
		self.Description = None
		self.AltTargetDomainName = None
		self.KDCServer = None
		self.unk10586_d = None
		self.ClientName = None
		self.name0 = None
		self.TicketFlags = None
		self.unk2 = None
		self.KeyType = None
		self.Key = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None
		self.unk6 = None
		self.unk7 = None
		self.domain = None
		self.unk8 = None
		self.strangeNames = None
		self.unk9 = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_INTERNAL_TICKET_10()
		res.Flink = await PKIWI_KERBEROS_INTERNAL_TICKET_10.load(reader)
		res.Blink = await PKIWI_KERBEROS_INTERNAL_TICKET_10.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.ServiceName = await PKERB_EXTERNAL_NAME.load(reader)
		res.TargetName  = await PKERB_EXTERNAL_NAME.load(reader)
		res.DomainName  = await LSA_UNICODE_STRING.load(reader)
		res.TargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.Description = await LSA_UNICODE_STRING.load(reader)
		res.AltTargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.KDCServer  = await LSA_UNICODE_STRING.load(reader)#	//?(reader).value
		res.unk10586_d = await LSA_UNICODE_STRING.load(reader)#	//?(reader).value
		res.ClientName = await PKERB_EXTERNAL_NAME.load(reader)
		res.name0 = await PVOID.loadvalue(reader)
		x = await reader.read(4)
		res.TicketFlags = int.from_bytes(x, byteorder = 'big', signed = False)
		res.unk2 = await ULONG.loadvalue(reader)
		res.KeyType = await ULONG.loadvalue(reader)
		await reader.align()
		res.Key  = await KIWI_KERBEROS_BUFFER.load(reader)
		res.unk3 = await PVOID.loadvalue(reader)
		res.unk4 = await PVOID.loadvalue(reader)
		res.unk5 = await PVOID.loadvalue(reader)
		await reader.align(8)
		res.StartTime  = await FILETIME.loadvalue(reader)
		res.EndTime    = await FILETIME.loadvalue(reader)
		res.RenewUntil = await FILETIME.loadvalue(reader)
		res.unk6 = await ULONG.loadvalue(reader)
		res.unk7 = await ULONG.loadvalue(reader)
		res.domain = await PCWSTR.loadvalue(reader)
		res.unk8   = await ULONG.loadvalue(reader)
		await reader.align()
		res.strangeNames  = await PVOID.loadvalue(reader)
		res.unk9          = await ULONG.loadvalue(reader)
		res.TicketEncType = await ULONG.loadvalue(reader)
		res.TicketKvno    = await ULONG.loadvalue(reader)
		await reader.align()
		res.Ticket = await KIWI_KERBEROS_BUFFER.load(reader)

class PKIWI_KERBEROS_INTERNAL_TICKET_11(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_INTERNAL_TICKET_11()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_INTERNAL_TICKET_11
		return p

		
class KIWI_KERBEROS_INTERNAL_TICKET_11:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.ServiceName = None
		self.TargetName = None
		self.DomainName = None
		self.TargetDomainName = None
		self.Description = None
		self.AltTargetDomainName = None
		self.KDCServer = None
		self.unk10586_d = None
		self.ClientName = None
		self.name0 = None
		self.TicketFlags = None
		self.unk2 = None
		self.unk14393_0 = None
		self.unk2x = None
		self.KeyType = None
		self.Key = None
		self.unk14393_1 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None
		self.unk6 = None
		self.unk7 = None
		self.domain = None
		self.unk8 = None
		self.strangeNames = None
		self.unk9 = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None
	

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_INTERNAL_TICKET_11()
		res.Flink = await PKIWI_KERBEROS_INTERNAL_TICKET_11.load(reader)
		res.Blink = await PKIWI_KERBEROS_INTERNAL_TICKET_11.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.ServiceName = await PKERB_EXTERNAL_NAME.load(reader)
		res.TargetName  = await PKERB_EXTERNAL_NAME.load(reader)
		res.DomainName          = await LSA_UNICODE_STRING.load(reader)
		res.TargetDomainName    = await LSA_UNICODE_STRING.load(reader)
		res.Description         = await LSA_UNICODE_STRING.load(reader)
		res.AltTargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.KDCServer           = await LSA_UNICODE_STRING.load(reader)    				#	//?(reader).value
		res.unk10586_d          = await LSA_UNICODE_STRING.load(reader)					#//?(reader).value
		res.ClientName = await PKERB_EXTERNAL_NAME.load(reader)
		res.name0 = await PVOID.loadvalue(reader)
		x = await reader.read(4)
		res.TicketFlags = int.from_bytes(x, byteorder = 'big', signed = False)
		res.unk2       = await ULONG.loadvalue(reader)
		res.unk14393_0 = await PVOID.loadvalue(reader)
		res.unk2x       = await ULONG.loadvalue(reader)
		res.KeyType    = await ULONG.loadvalue(reader)
		res.Key = await KIWI_KERBEROS_BUFFER.load(reader)
		res.unk14393_1 = await PVOID.loadvalue(reader)
		res.unk3       = await PVOID.loadvalue(reader)										# // ULONG		KeyType2 = (reader).value
		res.unk4       = await PVOID.loadvalue(reader)										# // KIWI_KERBEROS_BUFFER	Key2 = (reader).value
		res.unk5       = await PVOID.loadvalue(reader)										# // up(reader).value
		res.StartTime  = await FILETIME.loadvalue(reader)
		res.EndTime    = await FILETIME.loadvalue(reader)
		res.RenewUntil = await FILETIME.loadvalue(reader)
		res.unk6 = await ULONG.loadvalue(reader)
		res.unk7 = await ULONG.loadvalue(reader)
		res.domain = await PCWSTR.loadvalue(reader)
		res.unk8 = await ULONG.loadvalue(reader)
		await reader.align()
		res.strangeNames  = await PVOID.loadvalue(reader)
		res.unk9          = await ULONG.loadvalue(reader)
		res.TicketEncType = await ULONG.loadvalue(reader)
		res.TicketKvno    = await ULONG.loadvalue(reader)
		await reader.align()
		res.Ticket = await KIWI_KERBEROS_BUFFER.load(reader)

		return res

class PKIWI_KERBEROS_INTERNAL_TICKET_10_1607(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_INTERNAL_TICKET_10_1607()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_INTERNAL_TICKET_10_1607
		return p

		
class KIWI_KERBEROS_INTERNAL_TICKET_10_1607:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.ServiceName = None
		self.TargetName = None
		self.DomainName = None
		self.TargetDomainName = None
		self.Description = None
		self.AltTargetDomainName = None
		self.KDCServer = None
		self.unk10586_d = None
		self.ClientName = None
		self.name0 = None
		self.TicketFlags = None
		self.unk2 = None
		self.unk14393_0 = None
		self.KeyType = None
		self.Key = None
		self.unk14393_1 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None
		self.unk6 = None
		self.unk7 = None
		self.domain = None
		self.unk8 = None
		self.strangeNames = None
		self.unk9 = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None
	

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_INTERNAL_TICKET_10_1607()
		res.Flink = await PKIWI_KERBEROS_INTERNAL_TICKET_10_1607.load(reader)
		res.Blink = await PKIWI_KERBEROS_INTERNAL_TICKET_10_1607.load(reader)
		res.unk0 = await PVOID.loadvalue(reader)
		res.unk1 = await PVOID.loadvalue(reader)
		res.ServiceName = await PKERB_EXTERNAL_NAME.load(reader)
		res.TargetName  = await PKERB_EXTERNAL_NAME.load(reader)
		res.DomainName          = await LSA_UNICODE_STRING.load(reader)
		res.TargetDomainName    = await LSA_UNICODE_STRING.load(reader)
		res.Description         = await LSA_UNICODE_STRING.load(reader)
		res.AltTargetDomainName = await LSA_UNICODE_STRING.load(reader)
		res.KDCServer           = await LSA_UNICODE_STRING.load(reader)    				#	//?(reader).value
		res.unk10586_d          = await LSA_UNICODE_STRING.load(reader)					#//?(reader).value
		res.ClientName = await PKERB_EXTERNAL_NAME.load(reader)
		res.name0 = await PVOID.loadvalue(reader)
		x = await reader.read(4)
		res.TicketFlags = int.from_bytes(x, byteorder = 'big', signed = False)
		res.unk2       = await ULONG.loadvalue(reader)
		res.unk14393_0 = await PVOID.loadvalue(reader)
		res.KeyType    = await ULONG.loadvalue(reader)
		await reader.align()
		res.Key = await KIWI_KERBEROS_BUFFER.load(reader)
		res.unk14393_1 = await PVOID.loadvalue(reader)
		res.unk3       = await PVOID.loadvalue(reader)										# // ULONG		KeyType2 = (reader).value
		res.unk4       = await PVOID.loadvalue(reader)										# // KIWI_KERBEROS_BUFFER	Key2 = (reader).value
		res.unk5       = await PVOID.loadvalue(reader)										# // up(reader).value
		res.StartTime  = await FILETIME.loadvalue(reader)
		res.EndTime    = await FILETIME.loadvalue(reader)
		res.RenewUntil = await FILETIME.loadvalue(reader)
		res.unk6 = await ULONG.loadvalue(reader)
		res.unk7 = await ULONG.loadvalue(reader)
		res.domain = await PCWSTR.loadvalue(reader)
		res.unk8 = await ULONG.loadvalue(reader)
		await reader.align()
		res.strangeNames  = await PVOID.loadvalue(reader)
		res.unk9          = await ULONG.loadvalue(reader)
		res.TicketEncType = await ULONG.loadvalue(reader)
		res.TicketKvno    = await ULONG.loadvalue(reader)
		await reader.align()
		res.Ticket = await KIWI_KERBEROS_BUFFER.load(reader)

		return res

class PKERB_HASHPASSWORD_GENERIC(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKERB_HASHPASSWORD_GENERIC()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KERB_HASHPASSWORD_GENERIC
		return p
		
class KERB_HASHPASSWORD_GENERIC:
	def __init__(self):
		self.Type = None
		self.Size = None
		self.Checksump = None

	@staticmethod
	async def load(reader):
		res = KERB_HASHPASSWORD_GENERIC()
		res.Type = await DWORD.loadvalue(reader)
		await reader.align()
		res.Size      = await SIZE_T.loadvalue(reader)
		res.Checksump = await PVOID.load(reader) #loadvalue before?
		return res
	

class PKERB_HASHPASSWORD_5(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKERB_HASHPASSWORD_5()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KERB_HASHPASSWORD_5
		return p
		
class KERB_HASHPASSWORD_5:
	def __init__(self):
		self.salt = None
		self.generic = None
	
	@staticmethod
	async def load(reader):
		res = KERB_HASHPASSWORD_5()
		res.salt = await LSA_UNICODE_STRING.load(reader) #	// http://tools.ietf.org/html/rfc3962
		res.generic = await KERB_HASHPASSWORD_GENERIC.load(reader)
		return res

class PKERB_HASHPASSWORD_6(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKERB_HASHPASSWORD_6()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KERB_HASHPASSWORD_6
		return p
		
class KERB_HASHPASSWORD_6 :
	def __init__(self):
		self.salt = None
		self.stringToKey = None
		self.generic = None

	@staticmethod
	async def load(reader):
		res = KERB_HASHPASSWORD_6()
		res.salt = await LSA_UNICODE_STRING.load(reader)	#// http://tools.ietf.org/html/rfc3962
		res.stringToKey = await PVOID.load(reader) # // AES Iterations (dword ?)
		res.generic = await KERB_HASHPASSWORD_GENERIC.load(reader)
		return res

class PKERB_HASHPASSWORD_6_1607(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKERB_HASHPASSWORD_6_1607()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KERB_HASHPASSWORD_6_1607
		return p


class KERB_HASHPASSWORD_6_1607:
	def __init__(self):
		self.salt = None
		self.stringToKey = None
		self.unk0 = None
		self.generic = None
	
	@staticmethod
	async def load(reader):
		res = KERB_HASHPASSWORD_6_1607()
		res.salt = await LSA_UNICODE_STRING.load(reader)  #	// http://tools.ietf.org/html/rfc3962(reader).value
		res.stringToKey = await PVOID.loadvalue(reader)        # // AES Iterations (dword ?)(reader).value
		res.unk0 = await PVOID.loadvalue(reader)
		res.generic = await KERB_HASHPASSWORD_GENERIC.load(reader)
		return res

class PKIWI_KERBEROS_KEYS_LIST_5(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_KEYS_LIST_5()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_KEYS_LIST_5
		return p

class KIWI_KERBEROS_KEYS_LIST_5:
	def __init__(self):
		self.unk0 = None
		self.cbItem = None
		self.unk1 = None
		self.unk2 = None
		#//KERB_HASHPASSWORD_5 KeysEntries[ANYSIZE_ARRAY] = (reader).value
		self.KeyEntries_start = None
		self.KeyEntries = []

	async def read(self, reader, keyentries_type):
		await reader.move(self.KeyEntries_start)
		for _ in range(self.cbItem):
			ke = await keyentries_type.load(reader)
			self.KeyEntries.append(ke)
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_KEYS_LIST_5()
		res.unk0   = await DWORD.loadvalue(reader)		#// dword_1233EC8 dd 4
		res.cbItem = await DWORD.loadvalue(reader)	#// debug048:01233ECC dd 5(reader).value
		res.unk1   = await PVOID.loadvalue(reader)
		res.unk2   = await PVOID.loadvalue(reader)
		res.KeyEntries_start = reader.tell()
		return res


class PKIWI_KERBEROS_KEYS_LIST_6(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_KEYS_LIST_6()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_KEYS_LIST_6
		return p

class KIWI_KERBEROS_KEYS_LIST_6:
	def __init__(self):
		self.unk0   = None	#	// dword_1233EC8 dd 4(reader).value
		self.cbItem = None #	// debug048:01233ECC dd 5(reader).value
		self.unk1   = None
		self.unk2   = None
		self.unk3   = None
		self.unk4   = None
		self.KeyEntries_start = None
		self.KeyEntries = []
		
	async def read(self, reader, keyentries_type):
		await reader.move(self.KeyEntries_start)
		for _ in range(self.cbItem):
			ke = await keyentries_type.load(reader)
			self.KeyEntries.append(ke)
			#//KERB_HASHPASSWORD_6 KeysEntries[ANYSIZE_ARRAY] = (reader).value
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_KEYS_LIST_6()
		res.unk0   = await DWORD.loadvalue(reader)	#	// dword_1233EC8 dd 4(reader).value
		res.cbItem = await DWORD.loadvalue(reader) #	// debug048:01233ECC dd 5(reader).value
		res.unk1   = await PVOID.loadvalue(reader)
		res.unk2   = await PVOID.loadvalue(reader)
		res.unk3   = await PVOID.loadvalue(reader)
		res.unk4   = await PVOID.loadvalue(reader)
		res.KeyEntries_start = reader.tell()
		return res

class PKIWI_KERBEROS_ENUM_DATA_TICKET(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_KERBEROS_ENUM_DATA_TICKET()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_KERBEROS_ENUM_DATA_TICKET
		return p

class KIWI_KERBEROS_ENUM_DATA_TICKET:
	def __init__(self):
		self.isTicketExport = None
		self.isFullTicket = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_ENUM_DATA_TICKET()
		res.isTicketExport = await BOOL.loadvalue(reader)
		res.isFullTicket   = await BOOL.loadvalue(reader)
		return res
		
class KIWI_KERBEROS_BUFFER:
	def __init__(self):
		self.Length = None
		self.Value = None
		
		##not part of struct
		self.Data = None
		
	async def read(self, reader):
		await reader.move(self.Value.value)
		self.Data = await reader.read(self.Length)
		return self.Data

	@staticmethod
	async def load(reader):
		res = KIWI_KERBEROS_BUFFER()
		res.Length = await ULONG.loadvalue(reader)
		await reader.align()
		res.Value   = await PVOID.load(reader)
		return res