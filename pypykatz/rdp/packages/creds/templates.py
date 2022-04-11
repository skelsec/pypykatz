
from pypykatz.commons.common import KatzSystemArchitecture, WindowsBuild, WindowsMinBuild
from pypykatz.commons.win_datatypes import POINTER, ULONG, \
	KIWI_GENERIC_PRIMARY_CREDENTIAL, PVOID, DWORD, LUID, \
	LSA_UNICODE_STRING, WORD
from minidump.win_datatypes import PCWSTR
from pypykatz.commons.common import hexdump

class RDPCredsTemplate:
	def __init__(self):
		self.signatures = None
		self.signature = None

		self.cred_struct = None
		self.property_struct = None
		self.properties_struct = None

	@staticmethod
	def get_logonpasswords_template(sysinfo):
		template = RDPCredsTemplate()

		if sysinfo.buildnumber >= WindowsBuild.WIN_8.value:
			template.signatures = [b'\x00\x00\x00\x00\xbb\x47', b'\x00\x00\x00\x00\xf3\x47', b'\x00\x00\x00\x00\x3b\x01']
			template.offset = 0
			template.cred_struct = WTS_KIWI
		
		else:
			template.signatures = [b'\xc8\x00\x00\x00\xc8\x00\x00\x00']
			template.offset = 16
			template.cred_struct = WTS_KIWI_2008R2
		
		return template

	@staticmethod
	def get_mstsc_template():
		template = RDPCredsTemplate()

		template.signature = b'\xcd\xab\xca\xdb\x03'
		template.property_struct = TS_PROPERTY_KIWI
		template.properties_struct = TS_PROPERTIES_KIWI
		
		return template

# See mimikatz/modules/kuhl_m_ts.h
class PTS_PROPERTY_KIWI(POINTER):
	def __init__(self, reader):
		super().__init__(reader, TS_PROPERTY_KIWI)

class TS_PROPERTY_KIWI:
	def __init__(self, reader):
		reader.align()
		self.szProperty = PCWSTR(reader).value
		self.dwType = DWORD(reader).value
		reader.align()
		self.pvData = PVOID(reader).value
		self.unkp0 = PVOID(reader).value
		self.unkd0 = DWORD(reader).value
		self.dwFlags = DWORD(reader).value
		self.unkd1 = DWORD(reader).value
		self.unkd2 = DWORD(reader).value
		self.pValidator = PVOID(reader).value
		self.unkp2 = PVOID(reader).value
		self.unkp3 = PVOID(reader).value

class TS_PROPERTIES_KIWI:
	def __init__(self, reader):
		#self.unkp0 = PVOID(reader).value
		#self.unkp1 = PVOID(reader).value 
		self.unkh0 = DWORD(reader).value # 0xdbcaabcd
		self.unkd0 = DWORD(reader).value # 3
		self.unkp2 = PVOID(reader).value
		self.unkd1 = DWORD(reader).value # 45
		reader.align()
		self.unkp3 = PVOID(reader).value
		reader.align()
		self.pProperties_addr = reader.tell()
		self.pProperties = PVOID(reader)#PTS_PROPERTY_KIWI(reader)
		self.cbProperties = DWORD(reader).value

class WTS_KIWI:
	def __init__(self, reader):
		self.unk0 = DWORD(reader)
		self.unk1 = DWORD(reader)
		self.cbDomain = WORD(reader).value
		self.cbUsername = WORD(reader).value
		self.cbPassword = WORD(reader).value
		self.unk2 = DWORD(reader)
		self.Domain = reader.read(512)
		self.UserName = reader.read(512)
		self.Password_addr = reader.tell()
		self.Password = reader.read(512)

class WTS_KIWI_2008R2:
	def __init__(self, reader):
		self.unk0 = DWORD(reader)
		self.unk1 = DWORD(reader)
		self.cbDomain = WORD(reader).value + 511 #making it compatible with the other version. this is probably a bool?
		self.cbUsername = WORD(reader).value + 511
		self.cbPassword = WORD(reader).value + 511
		self.unk2 = DWORD(reader)
		self.Domain = reader.read(512)
		self.UserName = reader.read(512)
		self.Password_addr = reader.tell()
		self.Password = reader.read(512)