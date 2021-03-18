#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


from minidump.win_datatypes import ULONG, PVOID, POINTER
from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from pypykatz.lsadecryptor.package_commons import PackageTemplate

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
				keys = [x for x in templates['nt6']['x86']]
				keys.sort(reverse = True)
				for key in keys:
					yield templates['nt6']['x86'][key]

		elif sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception('NT 5 is not yet supported!')
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception('NT 5 is not yet supported!')
			else:
				keys = [x for x in templates['nt6']['x64']]
				keys.sort(reverse = True)
				for key in keys:
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
				#1
				template = templates['nt6']['x86']['1']
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 5
				#key_pattern.offset_to_DES_key_ptr = -76
				#key_pattern.offset_to_AES_key_ptr = -21
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				#2
				template = templates['nt6']['x86']['2']
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 5
				#key_pattern.offset_to_DES_key_ptr = -76
				#key_pattern.offset_to_AES_key_ptr = -21
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				#3
				template = templates['nt6']['x86']['3']
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 5
				#key_pattern.offset_to_DES_key_ptr = -69
				#key_pattern.offset_to_AES_key_ptr = -18
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY8
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:
				#4
				template = templates['nt6']['x86']['4']
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 5
				#
				#key_pattern.offset_to_DES_key_ptr = -69
				#key_pattern.offset_to_AES_key_ptr = -18
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY81
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_10.value <= sysinfo.buildnumber <= WindowsBuild.WIN_10_1507.value:
				#5
				template = templates['nt6']['x86']['5']

				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 5
				#key_pattern.offset_to_DES_key_ptr = -79
				#key_pattern.offset_to_AES_key_ptr = -22
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY81
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
				
			elif sysinfo.buildnumber > WindowsBuild.WIN_10_1507.value:
				#6
				template = templates['nt6']['x86']['6']
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 5
				#key_pattern.offset_to_DES_key_ptr = -79
				#key_pattern.offset_to_AES_key_ptr = -22
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY81
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
		
		elif sysinfo.architecture == KatzSystemArchitecture.X64:
		
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				#vista
				#1
				template = templates['nt6']['x64']['1']
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 63
				#key_pattern.offset_to_DES_key_ptr = -69
				#key_pattern.offset_to_AES_key_ptr = 25
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
		
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				#win 7
				#2
				template = templates['nt6']['x64']['2']

				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 59
				#key_pattern.offset_to_DES_key_ptr = -61
				#key_pattern.offset_to_AES_key_ptr = 25
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
			
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:
				#win 8 and blue
				#3
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 62
				#key_pattern.offset_to_DES_key_ptr = -70
				#key_pattern.offset_to_AES_key_ptr = 23
				
				if sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
					template = templates['nt6']['x64']['3']
					#win8
					#3
					#template.key_pattern = key_pattern
					#template.key_struct = KIWI_BCRYPT_KEY8
					#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
				else:
					template = templates['nt6']['x64']['4']
					#4
					#win blue
					#template.key_pattern = key_pattern
					#template.key_struct = KIWI_BCRYPT_KEY81
					#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
			
			
			elif sysinfo.buildnumber < WindowsBuild.WIN_10_1809.value:
				template = templates['nt6']['x64']['5']
				#5
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 61
				#key_pattern.offset_to_DES_key_ptr = -73
				#key_pattern.offset_to_AES_key_ptr = 16
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY81
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY				
				
				
			#elif sysinfo.buildnumber <= WindowsBuild.WIN_10_1809.value:
			else:
				template = templates['nt6']['x64']['6']
				#1809
				#6
				#key_pattern = LSADecyptorKeyPattern()
				#key_pattern.signature = b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15'
				#key_pattern.IV_length = 16
				#key_pattern.offset_to_IV_ptr = 67
				#key_pattern.offset_to_DES_key_ptr = -89
				#key_pattern.offset_to_AES_key_ptr = 16
				#
				#template.key_pattern = key_pattern
				#template.key_struct = KIWI_BCRYPT_KEY81
				#template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
			
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
	def __init__(self, reader):
		self.cbSecret = ULONG(reader).value
		self.data = reader.read(self.cbSecret)
		
class KIWI_BCRYPT_KEY:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag = reader.read(4)
		self.type = ULONG(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value
		self.hardkey = KIWI_HARD_KEY(reader)
		
	def verify(self):
		return self.tag == b'KSSM'

class KIWI_BCRYPT_KEY8:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag  = reader.read(4)	# 'MSSK'
		self.type = ULONG(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value
		self.unk3 = ULONG(reader).value
		reader.align()
		self.unk4 = PVOID(reader).value	# before, align in x64
		self.hardkey = KIWI_HARD_KEY(reader)
		
	def verify(self):
		return self.tag == b'KSSM' 

class KIWI_BCRYPT_KEY81:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag  = reader.read(4)	# 'MSSK'
		self.type = ULONG(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value 
		self.unk3 = ULONG(reader).value
		self.unk4 = ULONG(reader).value
		reader.align()
		self.unk5 = PVOID(reader).value	#before, align in x64
		self.unk6 = ULONG(reader).value
		self.unk7 = ULONG(reader).value
		self.unk8 = ULONG(reader).value
		self.unk9 = ULONG(reader).value
		self.hardkey = KIWI_HARD_KEY(reader)
		
	def verify(self):
		return self.tag == b'KSSM' 
		

class PKIWI_BCRYPT_KEY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, KIWI_BCRYPT_KEY)

class KIWI_BCRYPT_HANDLE_KEY:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag = reader.read(4)	# 'UUUR'
		self.hAlgorithm = PVOID(reader).value
		self.ptr_key = PKIWI_BCRYPT_KEY(reader)
		self.unk0 = PVOID(reader).value
		
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