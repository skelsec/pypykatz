import io
import logging
from minidump.win_datatypes import *
from pypykatz.commons.common import *
from pypykatz.commons.win_datatypes import *

class WdigestTemplate:
	def __init__(self):
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
			
class WDIGEST_DECRYPTOR_TEMPLATE:
	def __init__(self, arch, buildnumber):
		self.arch = arch
		self.buildnumber = buildnumber
	
	def get_template(self):
		template = WdigestTemplate()
		template.list_entry = PWdigestListEntry
		if self.arch == 'x64':
			if WindowsMinBuild.WIN_XP.value <= self.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x48\x3b\xda\x74'
				template.first_entry_offset = -4
				
			elif WindowsMinBuild.WIN_2K3.value <= self.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x48\x3b\xda\x74'
				template.first_entry_offset = -4
			elif self.buildnumber >= WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x48\x3b\xd9\x74'
				template.first_entry_offset = -4
				
			else:
				raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (self.arch, self.buildnumber))
			
		
		elif self.arch == 'x86':
			if WindowsMinBuild.WIN_XP.value <= self.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x74\x18\x8b\x4d\x08\x8b\x11'
				template.first_entry_offset = -6
			elif WindowsMinBuild.WIN_2K3.value <= self.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x74\x18\x8b\x4d\x08\x8b\x11'
				template.first_entry_offset = -6
				
			elif WindowsMinBuild.WIN_VISTA.value <= self.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x74\x11\x8b\x0b\x39\x4e\x10'
				template.first_entry_offset = -6
				
			elif WindowsMinBuild.WIN_BLUE.value <= self.buildnumber < WindowsMinBuild.WIN_10.value:
				template.signature = b'\x74\x15\x8b\x0a\x39\x4e\x10'
				template.first_entry_offset = -4
			
			elif self.buildnumber >= WindowsMinBuild.WIN_10.value:
				template.signature = b'\x74\x15\x8b\x0a\x39\x4e\x10'
				template.first_entry_offset = -6
		
		else:
			raise Exception('Unknown architecture! %s' % self.arch)

			
		return template
		
class PWdigestListEntry(POINTER):
	def __init__(self, reader):
		super().__init__(reader, WdigestListEntry)
		
class WdigestListEntry:
	def __init__(self, reader):
		self.Flink = PWdigestListEntry(reader)
		self.Blink = PWdigestListEntry(reader)
		self.usage_count = ULONG(reader)
		reader.align()
		self.this_entry = PWdigestListEntry(reader)
		self.luid = LUID(reader).value
		self.flag = int.from_bytes(reader.read(8), byteorder = 'little', signed = False) 
		self.UserName = LSA_UNICODE_STRING(reader)
		self.DomainName = LSA_UNICODE_STRING(reader)
		self.Password = LSA_UNICODE_STRING(reader)
		