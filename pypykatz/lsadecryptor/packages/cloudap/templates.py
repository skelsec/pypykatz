from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from pypykatz.commons.win_datatypes import ULONG, LUID, KIWI_GENERIC_PRIMARY_CREDENTIAL, POINTER, DWORD, PVOID, PSID, GUID, DWORD64
from pypykatz.lsadecryptor.package_commons import PackageTemplate

class CloudapTemplate(PackageTemplate):
	def __init__(self):
		super().__init__('Cloudap')
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None

	@staticmethod
	def get_template(sysinfo):
		template = CloudapTemplate()
		if sysinfo.buildnumber <= WindowsBuild.WIN_10_1903.value:
			return None

		if sysinfo.architecture == KatzSystemArchitecture.X64:
			template.signature = b'\x44\x8b\x01\x44\x39\x42\x18\x75'
			template.first_entry_offset = -9
			template.list_entry = PKIWI_CLOUDAP_LOGON_LIST_ENTRY
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			template.signature = b'\x8b\x31\x39\x72\x10\x75'
			template.first_entry_offset = -8
			template.list_entry = PKIWI_CLOUDAP_LOGON_LIST_ENTRY

		else:
			raise Exception('Could not identify template! Architecture: %s sysinfo.buildnumber: %s' % (sysinfo.architecture, sysinfo.buildnumber))
			
		template.log_template('list_entry', template.list_entry)
		return template

class PKIWI_CLOUDAP_CACHE_UNK(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CLOUDAP_CACHE_UNK)

class KIWI_CLOUDAP_CACHE_UNK:
	def __init__(self, reader):
		self.unk0 = DWORD(reader)
		self.unk1 = DWORD(reader)
		self.unk2 = DWORD(reader)
		self.unkSize = DWORD(reader).value
		self.guid = GUID(reader)
		self.unk = reader.read(64)


class PKIWI_CLOUDAP_CACHE_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CLOUDAP_CACHE_LIST_ENTRY)

class KIWI_CLOUDAP_CACHE_LIST_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_CLOUDAP_CACHE_LIST_ENTRY(reader)
		self.Blink = PKIWI_CLOUDAP_CACHE_LIST_ENTRY(reader)
		self.unk0 = DWORD(reader)
		reader.align()
		self.LockList = PVOID(reader)
		self.unk1 = PVOID(reader)
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.unk4 = PVOID(reader)
		self.unk5 = PVOID(reader)
		self.unk6 = DWORD(reader)
		self.unk7 = DWORD(reader)
		self.unk8 = DWORD(reader)
		self.unk9 = DWORD(reader)
		self.unkLogin0 = PVOID(reader) #PCWSTR
		self.unkLogin1 = PVOID(reader) #PCWSTR
		self.toname = reader.read(130)  #wchar_t [64 + 1];
		reader.align()
		self.Sid = PSID(reader).value
		self.unk10 = DWORD(reader)
		self.unk11 = DWORD(reader)
		self.unk12 = DWORD(reader)
		self.unk13 = DWORD(reader)
		self.toDetermine = PKIWI_CLOUDAP_CACHE_UNK(reader)
		self.unk14 = PVOID(reader)
		self.cbPRT = DWORD(reader).value
		reader.align()
		self.PRT = PVOID(reader) #PBYTE(reader)

class PKIWI_CLOUDAP_LOGON_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CLOUDAP_LOGON_LIST_ENTRY)

class KIWI_CLOUDAP_LOGON_LIST_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_CLOUDAP_LOGON_LIST_ENTRY(reader)
		self.Blink = PKIWI_CLOUDAP_LOGON_LIST_ENTRY(reader)
		self.unk0 = DWORD(reader)
		self.unk1 = DWORD(reader)
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.unk2 = DWORD64(reader)
		self.unk3 = DWORD64(reader)
		self.cacheEntry = PKIWI_CLOUDAP_CACHE_LIST_ENTRY(reader)
