#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

#import io
#from minidump.win_datatypes import *
from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild
from pypykatz.commons.win_datatypes import LUID, ULONG, POINTER
from pypykatz.lsadecryptor.package_commons import PackageTemplate

class WdigestTemplate(PackageTemplate):
	def __init__(self):
		super().__init__('Wdigest')
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
		self.primary_offset = None
	
	@staticmethod
	def get_template(sysinfo):
		template = WdigestTemplate()

		if sysinfo.architecture == KatzSystemArchitecture.X64:
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x48\x3b\xda\x74'
				template.first_entry_offset = -4
				template.primary_offset = 36
				template.list_entry = PWdigestListEntry
				
			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x48\x3b\xda\x74'
				template.first_entry_offset = -4
				template.primary_offset = 48
				template.list_entry = PWdigestListEntry

			elif sysinfo.buildnumber >= WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x48\x3b\xd9\x74'
				template.first_entry_offset = -4
				template.primary_offset = 48
				template.list_entry = PWdigestListEntry
				
			else:
				raise Exception('Could not identify template! Architecture: %s sysinfo.buildnumber: %s' % (sysinfo.architecture, sysinfo.buildnumber))
			
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x74\x18\x8b\x4d\x08\x8b\x11'
				template.first_entry_offset = -6
				template.primary_offset = 36
				template.list_entry = PWdigestListEntryNT5

			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x74\x18\x8b\x4d\x08\x8b\x11'
				template.first_entry_offset = -6
				template.primary_offset = 28
				template.list_entry = PWdigestListEntryNT5
								
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x74\x11\x8b\x0b\x39\x4e\x10'
				template.first_entry_offset = -6
				template.primary_offset = 32
				template.list_entry = PWdigestListEntry
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:
				template.signature = b'\x74\x15\x8b\x0a\x39\x4e\x10'
				template.first_entry_offset = -4
				template.primary_offset = 32
				template.list_entry = PWdigestListEntry
			
			elif sysinfo.buildnumber >= WindowsMinBuild.WIN_10.value:
				template.signature = b'\x74\x15\x8b\x0a\x39\x4e\x10'
				template.first_entry_offset = -6
				template.primary_offset = 32
				template.list_entry = PWdigestListEntry
				
			else:
				template.signature = b'\x74\x15\x8b\x17\x39\x56\x10'
				template.first_entry_offset = -6
				template.primary_offset = 32
				template.list_entry = PWdigestListEntry
		
		else:
			raise Exception('Unknown architecture! %s' % sysinfo.architecture)
		
		template.log_template('list_entry', template.list_entry)
		return template
	

class PWdigestListEntry(POINTER):
	def __init__(self, reader):
		super().__init__(reader, WdigestListEntry)
		
class PWdigestListEntryNT5(POINTER):
	def __init__(self, reader):
		super().__init__(reader, WdigestListEntryNT5)
		
class WdigestListEntryNT5:
	def __init__(self, reader):
		self.Flink = PWdigestListEntryNT5(reader)
		self.Blink = PWdigestListEntryNT5(reader)
		self.this_entry = PWdigestListEntryNT5(reader)
		self.usage_count = ULONG(reader)
		reader.align() #8?
		self.luid = LUID(reader).value


class WdigestListEntry:
	def __init__(self, reader):
		self.Flink = PWdigestListEntry(reader)
		self.Blink = PWdigestListEntry(reader)
		self.usage_count = ULONG(reader)
		reader.align() #8?
		self.this_entry = PWdigestListEntry(reader)
		self.luid = LUID(reader).value