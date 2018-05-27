#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging
from minidump.win_datatypes import *
from pypykatz.commons.common import *
from pypykatz.commons.win_datatypes import *

class DpapiTemplate:
	def __init__(self):
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
			
class DPAPI_DECRYPTOR_TEMPLATE:
	def __init__(self, arch, buildnumber):
		self.arch = arch
		self.buildnumber = buildnumber
	
	def get_template(self):
		template = DpapiTemplate()
		
		if self.buildnumber < WindowsMinBuild.WIN_VISTA.value:
			template.list_entry = PKIWI_CREDMAN_LIST_ENTRY_5
		elif WindowsMinBuild.WIN_VISTA.value <= self.buildnumber < WindowsMinBuild.WIN_7.value:
			template.list_entry = PKIWI_CREDMAN_LIST_ENTRY_60
		else:
			template.list_entry = PKIWI_CREDMAN_LIST_ENTRY

		return template

class PKIWI_MASTERKEY_CACHE_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_MASTERKEY_CACHE_ENTRY)

		
class KIWI_MASTERKEY_CACHE_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_MASTERKEY_CACHE_ENTRY(reader)
		self.Blink = PKIWI_MASTERKEY_CACHE_ENTRY(reader)
		self.LogonId = LUID(reader).value
		self.KeyUid = GUID(reader).value
		self.insertTime = FILETIME(reader)
		self.keySize = ULONG(reader).value
		self.key = reader.read(self.keySize)
		
class CREDMAN_INFOS:
	def __init__(self, reader):
		self.structSize = ULONG(reader).value
		self.offsetFLink = ULONG(reader).value
		self.offsetUsername = ULONG(reader).value
		self.offsetDomain = ULONG(reader).value
		self.offsetCbPassword = ULONG(reader).value
		self.offsetPassword = ULONG(reader).value
		
class PKIWI_CREDMAN_LIST_ENTRY_5(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CREDMAN_LIST_ENTRY_5)
		
class KIWI_CREDMAN_LIST_ENTRY_5:
	def __init__(self, reader):
		self.cbEncPassword = ULONG(reader).value
		self.encPassword = PWSTR
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY_5
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY_5
		self.server1 = UNICODE_STRING
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.user = UNICODE_STRING(reader)
		self.unk8 = ULONG(reader).value
		self.server2 = UNICODE_STRING
	
class PKIWI_CREDMAN_LIST_ENTRY_60(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CREDMAN_LIST_ENTRY_60)

class KIWI_CREDMAN_LIST_ENTRY_60:
	def __init__(self, reader):
		self.cbEncPassword = ULONG(reader).value
		self.encPassword = PWSTR(reader)
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY_60
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY_60
		self.type = UNICODE_STRING(reader)
		self.unk5 = PVOID(reader)
		self.server1 = UNICODE_STRING(reader)
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.unk8 = PVOID(reader)
		self.unk9 = PVOID(reader)
		self.unk10 = PVOID(reader)
		self.user = UNICODE_STRING(reader)
		self.unk11 = ULONG(reader).value
		self.server2 = UNICODE_STRING(reader)
	
class PKIWI_CREDMAN_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CREDMAN_LIST_ENTRY)
		
class KIWI_CREDMAN_LIST_ENTRY:
	def __init__(self, reader):
		self.cbEncPassword = ULONG(reader)
		self.encPassword = PWSTR(reader)
		self.unk0 = ULONG(reader)
		self.unk1 = ULONG(reader)
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader)
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY(reader)
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY(reader)
		self.unk4 = LIST_ENTRY(reader)
		self.type = UNICODE_STRING(reader)
		self.unk5 = PVOID(reader)
		self.server1 = UNICODE_STRING(reader)
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.unk8 = PVOID(reader)
		self.unk9 = PVOID(reader)
		self.unk10 = PVOID(reader)
		self.user = UNICODE_STRING(reader)
		self.unk11 = ULONG(reader)
		self.server2 = UNICODE_STRING(reader)

class PKIWI_CREDMAN_LIST_STARTER(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CREDMAN_LIST_STARTER)
		
class KIWI_CREDMAN_LIST_STARTER:
	def __init__(self, reader):
		self.unk0 = ULONG(reader)
		self.start = PKIWI_CREDMAN_LIST_ENTRY(reader)
		#...
	
class PKIWI_CREDMAN_SET_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_CREDMAN_SET_LIST_ENTRY)
		
class KIWI_CREDMAN_SET_LIST_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_CREDMAN_SET_LIST_ENTRY(reader)
		self.Blink = PKIWI_CREDMAN_SET_LIST_ENTRY(reader)
		self.unk0 = ULONG(reader)
		self.list1 = PKIWI_CREDMAN_LIST_STARTER(reader)
		self.list2 = PKIWI_CREDMAN_LIST_STARTER(reader)
	
		
		
		