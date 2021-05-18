
from pypykatz.commons.common import KatzSystemArchitecture
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
		template.signature = b'\x00\x00\x00\x00\xbb\x47\x03' #b'\x00\x00\x00\x00\xbb\x47\x0b\x00'
		template.cred_struct = WTS_KIWI

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
		self.Password = reader.read(512)