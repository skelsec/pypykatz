#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz.alsadecryptor.win_datatypes import ULONG, PVOID, POINTER
from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class LsaTemplate_NT5(PackageTemplate):
	def __init__(self):
		self.signature = None
		self.feedback = None
		self.randomkey_ptr = None
		self.DESXKey_ptr = None
		self.key_struct = None


	@staticmethod
	def get_template_brute(sysinfo):
		raise Exception('Template guessing is not applicable for NT5')

	
	@staticmethod
	def get_template(sysinfo):
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
	def __init__(self):
		self.roundKey = []
	
	@staticmethod
	async def load(reader):
		s = SYMCRYPT_NT5_DES_EXPANDED_KEY()
		for _ in range(16):
			x = await reader.read(4)
			r = int.from_bytes(x, 'little', signed = False)
			x = await reader.read(4)
			l = int.from_bytes(x, 'little', signed = False)
			s.roundKey.append([r, l])
		return s
		
	def __str__(self):
		t = 'SYMCRYPT_NT5_DES_EXPANDED_KEY\r\n'
		for i, x in enumerate(self.roundKey):
			t += '%s L: %s R: %s\r\n' % (i, hex(x[0]), hex(x[1]))
		return t
		
class SYMCRYPT_NT5_DESX_EXPANDED_KEY:
	def __init__(self):
		self.inputWhitening = None
		self.outputWhitening = None
		self.desKey = None
	
	@staticmethod
	async def load(reader):
		s = SYMCRYPT_NT5_DESX_EXPANDED_KEY()
		s.inputWhitening = await reader.read(8)
		s.outputWhitening = await reader.read(8)
		s.desKey = await SYMCRYPT_NT5_DES_EXPANDED_KEY.load(reader)
		return s

	def __str__(self):
		t = 'SYMCRYPT_NT5_DESX_EXPANDED_KEY\r\n'
		t += 'inputWhitening : %s\r\n' % (self.inputWhitening.hex())
		t += 'outputWhitening : %s\r\n' % (self.outputWhitening.hex())
		t += 'desKey : %s\r\n' % (str(self.desKey))
		return t

class PSYMCRYPT_NT5_DESX_EXPANDED_KEY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PVOID()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = SYMCRYPT_NT5_DESX_EXPANDED_KEY
		return p

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