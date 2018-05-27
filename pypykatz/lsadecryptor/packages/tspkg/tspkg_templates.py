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

class TspkgTemplate:
	def __init__(self):
		self.signature = None
		self.avl_offset = None
		self.credential_struct = None
			
class TSPKG_DECRYPTOR_TEMPLATE:
	def __init__(self, arch, buildnumber):
		self.arch = arch
		self.buildnumber = buildnumber
	
	def get_template(self):
		template = TspkgTemplate()
		if self.arch == 'x64':
			template.signature = b'\x48\x83\xec\x20\x48\x8d\x0d'
			template.avl_offset = 7
			
			if self.buildnumber < WindowsBuild.WIN_10_1607.value:
				template.credential_struct = KIWI_TS_CREDENTIAL_x64
				
			elif self.buildnumber >= WindowsMinBuild.WIN_10_1607.value:
				template.credential_struct = KIWI_TS_CREDENTIAL_1607_x64
				
			else:
				#currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (self.arch, self.buildnumber))
			
		
		elif self.arch == 'x86':
			if self.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x8b\xff\x55\x8b\xec\x51\x56\xbe'
				template.avl_offset = 8
				template.credential_struct = KIWI_TS_CREDENTIAL
				
			elif WindowsMinBuild.WIN_8.value <= self.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x8b\xff\x53\xbb'
				template.avl_offset = 4
				template.credential_struct = KIWI_TS_CREDENTIAL
				
			elif WindowsMinBuild.WIN_BLUE.value <= self.buildnumber < WindowsBuild.WIN_10_1607.value:
				template.signature = b'\x8b\xff\x57\xbf'
				template.avl_offset = 4
				template.credential_struct = KIWI_TS_CREDENTIAL
				
			elif self.buildnumber >= WindowsBuild.WIN_10_1607.value:
				template.signature = b'\x8b\xff\x57\xbf'
				template.avl_offset = 4
				template.credential_struct = KIWI_TS_CREDENTIAL_1607
			
		else:
			raise Exception('Unknown architecture! %s' % self.arch)

			
		return template

class PKIWI_TS_PRIMARY_CREDENTIAL(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_TS_PRIMARY_CREDENTIAL)
	
class KIWI_TS_PRIMARY_CREDENTIAL:
	def __init__(self, reader):
		self.unk0 = PVOID(reader) #	// lock ?
		self.credentials = KIWI_GENERIC_PRIMARY_CREDENTIAL(reader)
	 

class KIWI_TS_CREDENTIAL:
	def __init__(self, reader):
		self.unk0 = reader.read(64)
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.unk1 = PVOID(reader)
		self.unk2 = PVOID(reader)
		self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)
	
class KIWI_TS_CREDENTIAL_x64:
	def __init__(self, reader):
		self.unk0 = reader.read(108) 
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.unk1 = PVOID(reader)
		self.unk2 = PVOID(reader)
		self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)

class KIWI_TS_CREDENTIAL_1607:
	def __init__(self, reader):
		self.unk0 = reader.read(68) 
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.unk1 = PVOID(reader)
		self.unk2 = PVOID(reader)
		self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)
	

class KIWI_TS_CREDENTIAL_1607_x64:
	def __init__(self, reader):
		self.unk0 = reader.read(112) 
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.unk1 = PVOID(reader)
		self.unk2 = PVOID(reader)
		self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)

	