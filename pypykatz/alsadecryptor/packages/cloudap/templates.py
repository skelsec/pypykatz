from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from pypykatz.alsadecryptor.win_datatypes import ULONG, LUID, KIWI_GENERIC_PRIMARY_CREDENTIAL, POINTER, DWORD, PVOID, PSID, GUID, DWORD64
from pypykatz.alsadecryptor.package_commons import PackageTemplate

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
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CLOUDAP_CACHE_UNK()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CLOUDAP_CACHE_UNK
		return p

class KIWI_CLOUDAP_CACHE_UNK:
	def __init__(self):
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unkSize = None
		self.guid = None
		self.unk = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CLOUDAP_CACHE_UNK()
		res.unk0 = await DWORD.load(reader)
		res.unk1 = await DWORD.load(reader)
		res.unk2 = await DWORD.load(reader)
		res.unkSize = await DWORD.loadvalue(reader)
		res.guid = await GUID.loadvalue(reader)
		res.unk = await reader.read(64)
		return res


class PKIWI_CLOUDAP_CACHE_LIST_ENTRY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CLOUDAP_CACHE_LIST_ENTRY()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CLOUDAP_CACHE_LIST_ENTRY
		return p

class KIWI_CLOUDAP_CACHE_LIST_ENTRY:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.LockList = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unk5 = None
		self.unk6 = None
		self.unk7 = None
		self.unk8 = None
		self.unk9 = None
		self.unkLogin0 = None
		self.unkLogin1 = None
		self.toname = None
		self.Sid = None
		self.unk10 = None
		self.unk11 = None
		self.unk12 = None
		self.unk13 = None
		self.toDetermine = None
		self.unk14 = None
		self.cbPRT = None
		self.PRT = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CLOUDAP_CACHE_LIST_ENTRY()
		res.Flink = await PKIWI_CLOUDAP_CACHE_LIST_ENTRY.load(reader)
		res.Blink = await PKIWI_CLOUDAP_CACHE_LIST_ENTRY.load(reader)
		res.unk0 = await DWORD.load(reader)
		await reader.align()
		res.LockList = await PVOID.load(reader)
		res.unk1 = await PVOID.load(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.unk4 = await PVOID.load(reader)
		res.unk5 = await PVOID.load(reader)
		res.unk6 = await DWORD.load(reader)
		res.unk7 = await DWORD.load(reader)
		res.unk8 = await DWORD.load(reader)
		res.unk9 = await DWORD.load(reader)
		res.unkLogin0 = await PVOID.load(reader) #PCWSTR
		res.unkLogin1 = await PVOID.load(reader) #PCWSTR
		res.toname = await reader.read(130)  #wchar_t [64 + 1];
		await reader.align()
		res.Sid = await PSID.loadvalue(reader)
		res.unk10 = await DWORD.load(reader)
		res.unk11 = await DWORD.load(reader)
		res.unk12 = await DWORD.load(reader)
		res.unk13 = await DWORD.load(reader)
		res.toDetermine = await PKIWI_CLOUDAP_CACHE_UNK.load(reader)
		res.unk14 = await PVOID.load(reader)
		res.cbPRT = await DWORD.load(reader)
		await reader.align()
		res.PRT = await PVOID.load(reader) #PBYTE(reader)
		return res

class PKIWI_CLOUDAP_LOGON_LIST_ENTRY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CLOUDAP_LOGON_LIST_ENTRY()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CLOUDAP_LOGON_LIST_ENTRY
		return p

class KIWI_CLOUDAP_LOGON_LIST_ENTRY:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.unk1 = None
		self.LocallyUniqueIdentifier = None
		self.unk2 = None
		self.unk3 = None
		self.cacheEntry = None

	@staticmethod
	async def load(reader):
		res = KIWI_CLOUDAP_LOGON_LIST_ENTRY()
		res.Flink = await PKIWI_CLOUDAP_LOGON_LIST_ENTRY.load(reader)
		res.Blink = await PKIWI_CLOUDAP_LOGON_LIST_ENTRY.load(reader)
		res.unk0 = await DWORD.load(reader)
		res.unk1 = await DWORD.load(reader)
		res.LocallyUniqueIdentifier = await LUID.loadvalue(reader)
		res.unk2 = await DWORD64.load(reader)
		res.unk3 = await DWORD64.load(reader)
		res.cacheEntry = await PKIWI_CLOUDAP_CACHE_LIST_ENTRY.load(reader)
		return res