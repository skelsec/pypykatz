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

class SspTemplate:
	def __init__(self):
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
			
class SSP_DECRYPTOR_TEMPLATE:
	def __init__(self, arch, buildnumber):
		self.arch = arch
		self.buildnumber = buildnumber
	
	def get_template(self):
		template = SspTemplate()
		template.list_entry = PKIWI_SSP_CREDENTIAL_LIST_ENTRY
		
		if self.arch == 'x64':		
			if self.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\xc7\x43\x24\x43\x72\x64\x41\xff\x15'
				template.first_entry_offset = 16
				
			elif WindowsMinBuild.WIN_VISTA.value <= self.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\xc7\x47\x24\x43\x72\x64\x41\x48\x89\x47\x78\xff\x15'
				template.first_entry_offset = 20
				
			elif self.buildnumber >= WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x24\x43\x72\x64\x41\xff\x15'
				template.first_entry_offset = 14
			
			else:
				#currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (self.arch, self.buildnumber))
			
		
		elif self.arch == 'x86':
			template.signature = b'\x1c\x43\x72\x64\x41\xff\x15'
			template.first_entry_offset = 12
			
		else:
			raise Exception('Unknown architecture! %s' % self.arch)

			
		return template

class PKIWI_SSP_CREDENTIAL_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_SSP_CREDENTIAL_LIST_ENTRY)
		
class KIWI_SSP_CREDENTIAL_LIST_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_SSP_CREDENTIAL_LIST_ENTRY(reader)
		self.Blink = PKIWI_SSP_CREDENTIAL_LIST_ENTRY(reader)
		self.References = ULONG(reader).value
		self.CredentialReferences = ULONG(reader).value
		self.LogonId = LUID(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value
		reader.align()
		self.credentials = KIWI_GENERIC_PRIMARY_CREDENTIAL(reader)