
from pypykatz.commons.common import KatzSystemArchitecture, WindowsBuild, WindowsMinBuild
from pypykatz.commons.win_datatypes import POINTER, ULONG, \
	KIWI_GENERIC_PRIMARY_CREDENTIAL, PVOID, DWORD, LUID, \
	LSA_UNICODE_STRING, WORD
from pypykatz.commons.common import hexdump

class RDPCredsTemplate:
	def __init__(self):
		self.signature = None
		self.cred_struct = None

	@staticmethod
	def get_template(sysinfo):
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
		self.unk0 = DWORD(reader)
		self.cbDomain = WORD(reader).value + 511 #making it compatible with the pother version. this is probably a bool?)
		self.cbUsername = WORD(reader).value + 511
		self.cbPassword = WORD(reader).value + 511
		self.unk2 = DWORD(reader)
		self.Domain = reader.read(512)
		self.UserName = reader.read(512)
		self.Password_addr = reader.tell()
		self.Password = reader.read(512)