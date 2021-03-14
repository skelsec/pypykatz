#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from pypykatz.commons.common import hexdump
from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild
from pypykatz.alsadecryptor.win_datatypes import LSA_UNICODE_STRING, ULONG, PVOID, PWSTR, POINTER, LIST_ENTRY
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class CredmanTemplate(PackageTemplate):
	def __init__(self):
		super().__init__('Credman')
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
		
	@staticmethod
	def get_template(sysinfo):
		template = CredmanTemplate()
		
		if sysinfo.architecture == KatzSystemArchitecture.X64:	
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_5
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_60
			else:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY
		else:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_5_X86
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_60_X86
			else:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_X86
			
		template.log_template('list_entry', template.list_entry)

		return template
	
class PKIWI_CREDMAN_LIST_ENTRY_5_X86(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_LIST_ENTRY_5_X86()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_LIST_ENTRY_5_X86
		return p
		
class KIWI_CREDMAN_LIST_ENTRY_5_X86:
	def __init__(self):
		self.cbEncPassword = None
		self.encPassword = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.UserName = None
		self.cbUserName = None
		self.Flink = None
		self.Blink = None
		self.server1 = None
		self.unk6 = None
		self.unk7 = None
		self.user = None
		self.unk8 = None
		self.server2 = None
	
	@staticmethod
	async def load(reader):
		#IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		res = KIWI_CREDMAN_LIST_ENTRY_5_X86()
		await reader.move(reader.tell() - 32)
		await reader.align() #not sure if it's needed here
		#
		res.cbEncPassword = await ULONG.loadvalue(reader)
		await reader.align()
		res.encPassword =await PWSTR.load(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.UserName =await PWSTR.load(reader)
		res.cbUserName = await ULONG.loadvalue(reader)
		await reader.align()
		res.Flink = await PKIWI_CREDMAN_LIST_ENTRY_5.load(reader)
		res.Blink = await PKIWI_CREDMAN_LIST_ENTRY_5.load(reader)
		res.server1 =await LSA_UNICODE_STRING.load(reader)
		res.unk6 = await PVOID.load(reader)
		res.unk7 = await PVOID.load(reader)
		res.user =await LSA_UNICODE_STRING.load(reader)
		res.unk8 = await ULONG.loadvalue(reader)
		await reader.align()
		res.server2 = await LSA_UNICODE_STRING.load(reader)
		return res
	
class PKIWI_CREDMAN_LIST_ENTRY_60_X86(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_LIST_ENTRY_60_X86()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_LIST_ENTRY_60_X86
		return p

class KIWI_CREDMAN_LIST_ENTRY_60_X86:
	def __init__(self):
		self.cbEncPassword = None
		self.encPassword = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.UserName = None
		self.cbUserName = None
		self.Flink = None
		self.Blink = None
		self.type = None
		self.unk5 = None
		self.server1 = None
		self.unk6 = None
		self.unk7 = None
		self.unk8 = None
		self.unk9 = None
		self.unk10 = None
		self.user = None
		self.unk11 = None
		self.server2 = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CREDMAN_LIST_ENTRY_60_X86()
		#IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		#
		await reader.move(reader.tell() - 32)
		await reader.align() #not sure if it's needed here
		res.cbEncPassword = await ULONG.loadvalue(reader)
		await reader.align()
		res.encPassword =await PWSTR.load(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.UserName =await PWSTR.load(reader)
		res.cbUserName = await ULONG.loadvalue(reader)
		await reader.align()
		res.Flink = await PKIWI_CREDMAN_LIST_ENTRY_60.load(reader)
		res.Blink = await PKIWI_CREDMAN_LIST_ENTRY_60.load(reader)
		res.type = await LSA_UNICODE_STRING.load(reader)
		res.unk5 = await PVOID.load(reader)
		res.server1 =await LSA_UNICODE_STRING.load(reader)
		res.unk6 = await PVOID.load(reader)
		res.unk7 = await PVOID.load(reader)
		res.unk8 = await PVOID.load(reader)
		res.unk9 = await PVOID.load(reader)
		res.unk10 = await PVOID.load(reader)
		res.user =await LSA_UNICODE_STRING.load(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		await reader.align()
		res.server2 =await LSA_UNICODE_STRING.load(reader)
		return res
	
class PKIWI_CREDMAN_LIST_ENTRY_X86(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_LIST_ENTRY_X86()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_LIST_ENTRY_X86
		return p
		
class KIWI_CREDMAN_LIST_ENTRY_X86:
	def __init__(self):
		self.cbEncPassword = None
		self.encPassword = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.UserName = None
		self.cbUserName = None
		self.Flink = None
		self.Blink = None
		self.unk4 = None
		self.type = None
		self.unk5 = None
		self.server1 = None
		self.unk6 = None
		self.unk7 = None
		self.unk8 = None
		self.unk9 = None
		self.unk10 = None
		self.user = None
		self.unk11 = None
		self.server2 = None

	@staticmethod
	async def load(reader):
		res = KIWI_CREDMAN_LIST_ENTRY_X86()
		#IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		#
		await reader.move(reader.tell() - 32)
		await reader.align() #not sure if it's needed here
		
		#
		res.cbEncPassword = await ULONG.loadvalue(reader)
		await reader.align()
		res.encPassword =await PWSTR.load(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.UserName =await PWSTR.load(reader)
		res.cbUserName = await ULONG.loadvalue(reader)
		await reader.align()
		res.Flink = await PKIWI_CREDMAN_LIST_ENTRY.load(reader)
		res.Blink = await PKIWI_CREDMAN_LIST_ENTRY.load(reader)
		res.unk4 = await LIST_ENTRY.load(reader)
		res.type =await LSA_UNICODE_STRING.load(reader)
		res.unk5 = await PVOID.load(reader)
		res.server1 =await LSA_UNICODE_STRING.load(reader)
		res.unk6 = await PVOID.load(reader)
		res.unk7 = await PVOID.load(reader)
		res.unk8 = await PVOID.load(reader)
		res.unk9 = await PVOID.load(reader)
		res.unk10 = await PVOID.load(reader)
		res.user =await LSA_UNICODE_STRING.load(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		await reader.align()
		res.server2 =await LSA_UNICODE_STRING.load(reader)
		return res
		
		
class PKIWI_CREDMAN_LIST_ENTRY_5(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_LIST_ENTRY_5()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_LIST_ENTRY_5
		return p
		
class KIWI_CREDMAN_LIST_ENTRY_5:
	def __init__(self):
		self.cbEncPassword = None
		self.encPassword = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.UserName = None
		self.cbUserName = None
		self.Flink = None
		self.Blink = None
		self.server1 = None
		self.unk6 = None
		self.unk7 = None
		self.user = None
		self.unk8 = None
		self.server2 = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CREDMAN_LIST_ENTRY_5()
		#IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		#
		await reader.move(reader.tell() - 56)
		await reader.align() #not sure if it's needed here
		res.cbEncPassword = await ULONG.loadvalue(reader)
		await reader.align()
		res.encPassword = await PWSTR.load(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.UserName = await PWSTR.load(reader)
		res.cbUserName = await ULONG.loadvalue(reader)
		await reader.align()
		res.Flink = await PKIWI_CREDMAN_LIST_ENTRY_5.load(reader)
		res.Blink = await PKIWI_CREDMAN_LIST_ENTRY_5.load(reader)
		res.server1 = await LSA_UNICODE_STRING.load(reader)
		res.unk6 = await PVOID.load(reader)
		res.unk7 = await PVOID.load(reader)
		res.user = await LSA_UNICODE_STRING.load(reader)
		res.unk8 = await ULONG.loadvalue(reader)
		await reader.align()
		res.server2 = LSA_UNICODE_STRING
		return res
	
class PKIWI_CREDMAN_LIST_ENTRY_60(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_LIST_ENTRY_60()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_LIST_ENTRY_60
		return p

class KIWI_CREDMAN_LIST_ENTRY_60:
	def __init__(self):
		self.cbEncPassword = None
		self.encPassword = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.UserName = None
		self.cbUserName = None
		self.Flink = None
		self.Blink = None
		self.type = None
		self.unk5 = None
		self.server1 = None
		self.unk6 = None
		self.unk7 = None
		self.unk8 = None
		self.unk9 = None
		self.unk10 = None
		self.user = None
		self.unk11 = None
		self.server2 = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CREDMAN_LIST_ENTRY_60()
		#IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		#
		await reader.move(reader.tell() - 56)
		await reader.align() #not sure if it's needed here
		#
		#input('KIWI_CREDMAN_LIST_ENTRY_60 \n%s' % hexdump(reader.peek(0x200), start = reader.tell()))
		#
		res.cbEncPassword = await ULONG.loadvalue(reader)
		await reader.align()
		res.encPassword =await PWSTR.load(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.UserName = await PWSTR.load(reader)
		res.cbUserName = await ULONG.loadvalue(reader)
		await reader.align()
		res.Flink = await PKIWI_CREDMAN_LIST_ENTRY_60.load(reader)
		res.Blink = await PKIWI_CREDMAN_LIST_ENTRY_60.load(reader)
		res.type =await LSA_UNICODE_STRING.load(reader)
		res.unk5 = await PVOID.load(reader)
		res.server1 =await LSA_UNICODE_STRING.load(reader)
		res.unk6 = await PVOID.load(reader)
		res.unk7 = await PVOID.load(reader)
		res.unk8 = await PVOID.load(reader)
		res.unk9 = await PVOID.load(reader)
		res.unk10 = await PVOID.load(reader)
		res.user =await LSA_UNICODE_STRING.load(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		await reader.align()
		res.server2 =await LSA_UNICODE_STRING.load(reader)
		return res
	
class PKIWI_CREDMAN_LIST_ENTRY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_LIST_ENTRY()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_LIST_ENTRY
		return p
		
class KIWI_CREDMAN_LIST_ENTRY:
	def __init__(self):
		self.cbEncPassword = None
		self.encPassword = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.UserName = None
		self.cbUserName = None
		self.Flink = None
		self.Blink = None
		self.unk4 = None
		self.type = None
		self.unk5 = None
		self.server1 = None
		self.unk6 = None
		self.unk7 = None
		self.unk8 = None
		self.unk9 = None
		self.unk10 = None
		self.user = None
		self.unk11 = None
		self.server2 = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CREDMAN_LIST_ENTRY()
		#IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		await reader.move(reader.tell() - 56)
		await reader.align() #not sure if it's needed here
		res.cbEncPassword = await ULONG.loadvalue(reader)
		await reader.align()
		res.encPassword =await PWSTR.load(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await PVOID.load(reader)
		res.unk3 = await PVOID.load(reader)
		res.UserName =await PWSTR.load(reader)
		res.cbUserName = await ULONG.loadvalue(reader)
		await reader.align()
		res.Flink = await PKIWI_CREDMAN_LIST_ENTRY.load(reader)
		res.Blink = await PKIWI_CREDMAN_LIST_ENTRY.load(reader)
		res.unk4 =await LIST_ENTRY.load(reader)
		res.type =await LSA_UNICODE_STRING.load(reader)
		res.unk5 = await PVOID.load(reader)
		res.server1 =await LSA_UNICODE_STRING.load(reader)
		res.unk6 = await PVOID.load(reader)
		res.unk7 = await PVOID.load(reader)
		res.unk8 = await PVOID.load(reader)
		res.unk9 = await PVOID.load(reader)
		res.unk10 = await PVOID.load(reader)
		res.user = await LSA_UNICODE_STRING.load(reader)
		res.unk11 = await ULONG.loadvalue(reader)
		await reader.align()
		res.server2 =await LSA_UNICODE_STRING.load(reader)
		return res

class PKIWI_CREDMAN_LIST_STARTER(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_LIST_STARTER()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_LIST_STARTER
		return p
		
class KIWI_CREDMAN_LIST_STARTER:
	def __init__(self):
		self.unk0 = None
		self.start = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CREDMAN_LIST_STARTER()
		res.unk0 = await ULONG.load(reader)
		await reader.align()
		res.start = await PKIWI_CREDMAN_LIST_ENTRY.load(reader)
		return res
	
class PKIWI_CREDMAN_SET_LIST_ENTRY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKIWI_CREDMAN_SET_LIST_ENTRY()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_CREDMAN_SET_LIST_ENTRY
		return p
		
class KIWI_CREDMAN_SET_LIST_ENTRY:
	def __init__(self):
		self.Flink = None
		self.Blink = None
		self.unk0 = None
		self.list1 = None
		self.list2 = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_CREDMAN_SET_LIST_ENTRY()
		res.Flink = await PKIWI_CREDMAN_SET_LIST_ENTRY.load(reader)
		res.Blink = await PKIWI_CREDMAN_SET_LIST_ENTRY.load(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		await reader.align()
		res.list1 = await PKIWI_CREDMAN_LIST_STARTER.load(reader)
		res.list2 = await PKIWI_CREDMAN_LIST_STARTER.load(reader)
		return res
		
		