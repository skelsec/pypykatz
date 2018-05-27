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
		template.list_entry = PKIWI_MASTERKEY_CACHE_ENTRY
		
		if self.arch == 'x64':		
			if self.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x4d\x3b\xee\x49\x8b\xfd\x0f\x85'
				template.first_entry_offset = -4
				
			elif WindowsMinBuild.WIN_VISTA.value <= self.buildnumber < WindowsMinBuild.WIN_7.value:
				template.signature = b'\x49\x3b\xef\x48\x8b\xfd\x0f\x84'
				template.first_entry_offset = -4
				
			elif WindowsMinBuild.WIN_7.value <= self.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x33\xc0\xeb\x20\x48\x8d\x05'
				template.first_entry_offset = 7
				
			elif WindowsMinBuild.WIN_8.value <= self.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x4c\x89\x1f\x48\x89\x47\x08\x49\x39\x43\x08\x0f\x85'
				template.first_entry_offset = -4

			elif WindowsMinBuild.WIN_BLUE.value <= self.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x08\x48\x39\x48\x08\x0f\x85'
				template.first_entry_offset = -10

			elif WindowsBuild.WIN_10_1507.value <= self.buildnumber < WindowsBuild.WIN_10_1607.value:
				template.signature = b'\x48\x89\x4e\x08\x48\x39\x48\x08'
				template.first_entry_offset = -7
				
			elif self.buildnumber >= WindowsBuild.WIN_10_1607.value:
				template.signature = b'\x48\x89\x4f\x08\x48\x89\x78\x08'
				template.first_entry_offset = 11
			
			else:
				#currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (self.arch, self.buildnumber))
			
		
		elif self.arch == 'x86':
			if self.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x33\xc0\x40\xa3'
				template.first_entry_offset = -4
				
			elif WindowsMinBuild.WIN_8.value <= self.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x8b\xf0\x81\xfe\xcc\x06\x00\x00\x0f\x84'
				template.first_entry_offset = -16
				
			elif self.buildnumber >= WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x33\xc0\x40\xa3'
				template.first_entry_offset = -4
			
		else:
			raise Exception('Unknown architecture! %s' % self.arch)

			
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
		
		
		
		
		
		
		
		
		