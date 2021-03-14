#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


from pypykatz.alsadecryptor.win_datatypes import ULONG, PVOID, POINTER
from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from pypykatz.alsadecryptor.package_commons import PackageTemplate

class LsaTemplate_NT6(PackageTemplate):
	def __init__(self):
		super().__init__('LSA Decryptor')
		self.key_pattern = None
		self.key_handle_struct = None
		self.key_struct = None
		self.hard_key_struct = KIWI_HARD_KEY
		self.nt_major = '6'


	@staticmethod
	def get_template_brute(sysinfo):
		if sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception('NT 5 is not yet supported!')
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception('NT 5 is not yet supported!')
			else:
				for key in templates['nt6']['x86']:
					yield templates['nt6']['x86'][key]

		elif sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception('NT 5 is not yet supported!')
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception('NT 5 is not yet supported!')
			else:
				for key in templates['nt6']['x64']:
					yield templates['nt6']['x64'][key]
		
		
	@staticmethod
	def get_template(sysinfo):
		template = LsaTemplate_NT6()
		
		if sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				template.nt_major = '5'
				template = templates['nt5']['x86']['1']
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template = templates['nt6']['x86']['1']
				
			elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template = templates['nt6']['x86']['2']
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template = templates['nt6']['x86']['3']
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:
				template = templates['nt6']['x86']['4']
				
			elif WindowsMinBuild.WIN_10.value <= sysinfo.buildnumber <= WindowsBuild.WIN_10_1507.value:
				template = templates['nt6']['x86']['5']
				
				
			elif sysinfo.buildnumber > WindowsBuild.WIN_10_1507.value:
				template = templates['nt6']['x86']['6']
		
		elif sysinfo.architecture == KatzSystemArchitecture.X64:
		
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template = templates['nt6']['x64']['1']
		
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template = templates['nt6']['x64']['2']
			
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:				
				if sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
					template = templates['nt6']['x64']['3']
				else:
					template = templates['nt6']['x64']['4']
			
			elif sysinfo.buildnumber < WindowsBuild.WIN_10_1809.value:
				template = templates['nt6']['x64']['5']
			else:
				template = templates['nt6']['x64']['6']
			
		else:
			raise Exception('Missing LSA decrpytor template for Architecture: %s , Build number %s' % (sysinfo.architecture, sysinfo.buildnumber))
		

		template.log_template('key_handle_struct', template.key_handle_struct)
		template.log_template('key_struct', template.key_struct)
		template.log_template('hard_key_struct', template.hard_key_struct)
		
		return template
		
		
class LSADecyptorKeyPattern:
	def __init__(self):
		self.signature = None #byte pattern that identifies the location of the key structures (AES and DES)
		self.offset_to_IV_ptr = None #offset from pattern that gives the pointer to the IV (applicabe for both keys, kept sepparately from key structures)
		self.IV_length = None #length of the IV, always 16 from NT6
		self.offset_to_AES_key_ptr = None #offset from signature that gives the pointer to the DES key structure
		self.offset_to_DES_key_ptr = None #offset from signature that gives the pointer to the AES key structure
		
class KIWI_HARD_KEY:
	def __init__(self):
		self.cbSecret = None
		self.data = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_BCRYPT_KEY()
		res.cbSecret = await ULONG.loadvalue(reader)
		res.data = await reader.read(res.cbSecret)
		return res
		
class KIWI_BCRYPT_KEY:
	def __init__(self):
		self.size = None
		self.tag  = None
		self.type = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.hardkey = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_BCRYPT_KEY()
		res.size = await ULONG.loadvalue(reader)
		res.tag  = await reader.read(4)
		res.type = await ULONG.loadvalue(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await ULONG.loadvalue(reader)
		res.hardkey = await KIWI_HARD_KEY.load(reader)
		return res
		
	def verify(self):
		return self.tag == b'KSSM'

class KIWI_BCRYPT_KEY8:
	def __init__(self):
		self.size = None
		self.tag  = None
		self.type = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		#await reader.align()
		self.unk4 = None
		self.hardkey = None

	@staticmethod
	async def load(reader):
		res = KIWI_BCRYPT_KEY8()
		res.size = await ULONG.loadvalue(reader)
		res.tag  = await reader.read(4)	# 'MSSK'
		res.type = await ULONG.loadvalue(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await ULONG.loadvalue(reader)
		res.unk3 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk4 = await PVOID.load(reader)	# before, align in x64
		res.hardkey = await KIWI_HARD_KEY.load(reader)
		return res
		
	def verify(self):
		return self.tag == b'KSSM' 

class KIWI_BCRYPT_KEY81:
	def __init__(self):
		self.size = None
		self.tag  = None
		self.type = None 
		self.unk0 = None 
		self.unk1 = None 
		self.unk2 = None  
		self.unk3 = None 
		self.unk4 = None 
		#await reader.align()
		self.unk5 = None	#before, align in x64
		self.unk6 = None
		self.unk7 = None
		self.unk8 = None
		self.unk9 = None
		self.hardkey = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_BCRYPT_KEY81()
		res.size = await ULONG.loadvalue(reader)
		res.tag  = await reader.read(4)	# 'MSSK'
		res.type = await ULONG.loadvalue(reader)
		res.unk0 = await ULONG.loadvalue(reader)
		res.unk1 = await ULONG.loadvalue(reader)
		res.unk2 = await ULONG.loadvalue(reader) 
		res.unk3 = await ULONG.loadvalue(reader)
		res.unk4 = await ULONG.loadvalue(reader)
		await reader.align()
		res.unk5 = await PVOID.load(reader)	#before, align in x64
		res.unk6 = await ULONG.loadvalue(reader)
		res.unk7 = await ULONG.loadvalue(reader)
		res.unk8 = await ULONG.loadvalue(reader)
		res.unk9 = await ULONG.loadvalue(reader)
		res.hardkey = await KIWI_HARD_KEY.load(reader)
		return res
		
	def verify(self):
		return self.tag == b'KSSM' 
		

class PKIWI_BCRYPT_KEY(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PVOID()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KIWI_BCRYPT_KEY
		return p

class KIWI_BCRYPT_HANDLE_KEY:
	def __init__(self):
		self.size = None
		self.tag = None
		self.hAlgorithm = None
		self.ptr_key = None
		self.unk0 = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_BCRYPT_HANDLE_KEY()
		res.size = await ULONG.loadvalue(reader)
		res.tag = await reader.read(4)	# 'UUUR'
		res.hAlgorithm = await PVOID.load(reader)
		res.ptr_key = await PKIWI_BCRYPT_KEY.load(reader)
		res.unk0 = await PVOID.load(reader)
		return res
		
	def verify(self):
		return self.tag == b'RUUU'

class LSA_x64_1(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 63
		self.key_pattern.offset_to_DES_key_ptr = -69
		self.key_pattern.offset_to_AES_key_ptr = 25
		
		self.key_struct = KIWI_BCRYPT_KEY
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x64_2(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 59
		self.key_pattern.offset_to_DES_key_ptr = -61
		self.key_pattern.offset_to_AES_key_ptr = 25
		
		self.key_struct = KIWI_BCRYPT_KEY
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

				
class LSA_x64_3(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 62
		self.key_pattern.offset_to_DES_key_ptr = -70
		self.key_pattern.offset_to_AES_key_ptr = 23
		
		self.key_struct = KIWI_BCRYPT_KEY8
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x64_4(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 62
		self.key_pattern.offset_to_DES_key_ptr = -70
		self.key_pattern.offset_to_AES_key_ptr = 23
		
		self.key_struct = KIWI_BCRYPT_KEY81
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY				

class LSA_x64_5(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 61
		self.key_pattern.offset_to_DES_key_ptr = -73
		self.key_pattern.offset_to_AES_key_ptr = 16
		
		self.key_struct = KIWI_BCRYPT_KEY81
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x64_6(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 67
		self.key_pattern.offset_to_DES_key_ptr = -89
		self.key_pattern.offset_to_AES_key_ptr = 16
				
		self.key_struct = KIWI_BCRYPT_KEY81
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x86_1(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 5
		self.key_pattern.offset_to_DES_key_ptr = -76
		self.key_pattern.offset_to_AES_key_ptr = -21

		self.key_struct = KIWI_BCRYPT_KEY
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x86_2(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 5
		self.key_pattern.offset_to_DES_key_ptr = -76
		self.key_pattern.offset_to_AES_key_ptr = -21
		
		self.key_struct = KIWI_BCRYPT_KEY
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x86_3(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 5
		self.key_pattern.offset_to_DES_key_ptr = -69
		self.key_pattern.offset_to_AES_key_ptr = -18
		
		self.key_struct = KIWI_BCRYPT_KEY8
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x86_4(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 5
		self.key_pattern.offset_to_DES_key_ptr = -69
		self.key_pattern.offset_to_AES_key_ptr = -18
		
		self.key_struct = KIWI_BCRYPT_KEY81
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x86_5(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)
		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 5
		self.key_pattern.offset_to_DES_key_ptr = -79
		self.key_pattern.offset_to_AES_key_ptr = -22
				
		self.key_struct = KIWI_BCRYPT_KEY81
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

class LSA_x86_6(LsaTemplate_NT6):
	def __init__(self):
		LsaTemplate_NT6.__init__(self)

		self.key_pattern = LSADecyptorKeyPattern()
		self.key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
		self.key_pattern.IV_length = 16
		self.key_pattern.offset_to_IV_ptr = 5
		self.key_pattern.offset_to_DES_key_ptr = -79
		self.key_pattern.offset_to_AES_key_ptr = -22

		self.key_struct = KIWI_BCRYPT_KEY81
		self.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY



templates = {
	'nt6' : {
		'x64' : {
			'1' : LSA_x64_1(),
			'2' : LSA_x64_2(),
			'3' : LSA_x64_3(),
			'4' : LSA_x64_4(),
			'5' : LSA_x64_5(),
			'6' : LSA_x64_6(),
		},
		'x86': {
			'1' : LSA_x86_1(),
			'2' : LSA_x86_2(),
			'3' : LSA_x86_3(),
			'4' : LSA_x86_4(),
			'5' : LSA_x86_5(),
			'6' : LSA_x86_6(),
		}
	}
}