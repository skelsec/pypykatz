#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import logging
from minidump.win_datatypes import *
from pypykatz.commons.common import *
from .package_commons import *

class LsaTemplate_NT5(PackageTemplate):
	def __init__(self):
		self.signature = None
		self.feedback = None
		self.randomkey_ptr = None
		self.DESXKey_ptr = None
		self.key_struct = None


	@staticmethod
	def get_template_brute(sysinfo):
		pass
		if sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception('NT 5 is not yet supported!')
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception('NT 5 is not yet supported!')
			else:
				raise Exception('NT 6 is in another castle!')

		elif sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception('NT 5 is not yet supported!')
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception('NT 5 is not yet supported!')
			else:
				raise Exception('NT 6 is in another castle!')

	
	@staticmethod
	def get_template(sysinfo):
		template = None
		print(sysinfo.buildnumber)
		if sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_VISTA.value:
				return templates['nt5']['x86']['1']
			else:
				raise Exception('NT 6 is in another castle!')

		elif sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_VISTA.value:
				return templates['nt5']['x64']['1']			
			else:
				raise Exception('NT 6 is in another castle!')

class SYMCRYPT_NT5_DES_EXPANDED_KEY:
	def __init__(self, reader):
		self.roundKey = []
		for _ in range(16):
			r = int.from_bytes(reader.read(4), 'big', signed = False)
			l = int.from_bytes(reader.read(4), 'big', signed = False)
			self.roundKey.append([r, l])
		
class SYMCRYPT_NT5_DESX_EXPANDED_KEY:
	def __init__(self, reader):
		input(hexdump(reader.peek(0x50), start = 0))
		self.inputWhitening = reader.read(8)
		self.outputWhitening = reader.read(8)
		self.desKey = SYMCRYPT_NT5_DES_EXPANDED_KEY(reader).roundKey

class PSYMCRYPT_NT5_DESX_EXPANDED_KEY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, SYMCRYPT_NT5_DESX_EXPANDED_KEY)

class LSA_x64_nt5_1(LsaTemplate_NT5):
	def __init__(self):
		LsaTemplate_NT5.__init__(self)
		self.arch = 'x64'
		self.signature = b'\x33\xdb\x8b\xc3\x48\x83\xc4\x20\x5b\xc3'
		self.nt_major = '5'
		self.feedback_ptr_offset = -67
		self.randomkey_ptr_offset = -17
		self.desx_key_ptr_offset = -35
		self.old_feedback_offset = 29
		self.key_struct_ptr = PSYMCRYPT_NT5_DESX_EXPANDED_KEY

class LSA_x86_nt5_1(LsaTemplate_NT5):
	def __init__(self):
		LsaTemplate_NT5.__init__(self)
		self.arch = 'x86'
		self.nt_major = '5'
		self.signature = b'\x05\x90\x00\x00\x00\x6a\x18\x50\xa3'
		self.feedback_ptr_offset = 25
		self.randomkey_ptr_offset = 9
		self.desx_key_ptr_offset = -4
		self.old_feedback_offset = 29
		self.key_struct_ptr = PSYMCRYPT_NT5_DESX_EXPANDED_KEY


templates = {
	'nt5' : {
		'x86': {
			'1' : LSA_x86_nt5_1(),
		},
		'x64': {
			'1' : LSA_x64_nt5_1(),
		}
	}
}