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

class LiveSspTemplate:
	def __init__(self):
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
			
class LIVESSP_DECRYPTOR_TEMPLATE:
	def __init__(self, arch, buildnumber):
		self.arch = arch
		self.buildnumber = buildnumber
	
	def get_template(self):
		template = LiveSspTemplate()
		template.list_entry = PKIWI_LIVESSP_LIST_ENTRY
		
		if self.arch == 'x64':		
			if self.buildnumber >= WindowsMinBuild.WIN_8.value:
				template.signature = b'\x74\x25\x8b'
				template.first_entry_offset = -7
			
			else:
				#currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (self.arch, self.buildnumber))
			
		
		elif self.arch == 'x86':
			if self.buildnumber >= WindowsMinBuild.WIN_8.value:
				template.signature = b'\x8b\x16\x39\x51\x24\x75\x08'
				template.first_entry_offset = -8
			
			else:
				#currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (self.arch, self.buildnumber))
			
		else:
			raise Exception('Unknown architecture! %s' % self.arch)

			
		return template

class PKIWI_LIVESSP_PRIMARY_CREDENTIAL(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_LIVESSP_PRIMARY_CREDENTIAL)
		
class KIWI_LIVESSP_PRIMARY_CREDENTIAL:
	def __init__(self, reader):
		self.isSupp = ULONG(reader).value
		self.unk0 = ULONG(reader).value
		self.credentials = KIWI_GENERIC_PRIMARY_CREDENTIAL(reader)


class PKIWI_LIVESSP_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_LIVESSP_LIST_ENTRY)
		
class KIWI_LIVESSP_LIST_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_LIVESSP_LIST_ENTRY(reader)
		self.Blink = PKIWI_LIVESSP_LIST_ENTRY(reader)
		self.unk0 = PVOID(reader)
		self.unk1 = PVOID(reader)
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.unk4 = DWORD(reader).value
		self.unk5 = DWORD(reader).value
		self.unk6 = PVOID(reader)
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.UserName = LSA_UNICODE_STRING(reader)
		self.unk7 = PVOID(reader)
		self.suppCreds = PKIWI_LIVESSP_PRIMARY_CREDENTIAL(reader)