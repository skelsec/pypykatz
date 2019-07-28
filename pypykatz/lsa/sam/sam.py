
import hashlib
import aiowinreg
from aiowinreg.hive import AIOWinRegHive
from pypykatz.lsa.sam.structures import *
from pypykatz.crypto.RC4 import RC4
from pypykatz.crypto.aes import AESModeOfOperationCBC, Decrypter
from pypykatz.crypto.des import *


class SYSTEM:
	def __init__(self, system_hive):
		self.hive = system_hive
		self.currentcontrol = None
		self.bootkey = None
		
	def get_currentcontrol(self):
		ccs = self.hive.get_value('Select\\Current')[1]
		print(ccs)
		self.currentcontrol = "ControlSet%03d" % ccs
		
	def get_bootkey(self):
		if self.bootkey is not None:
			return self.bootkey
		if self.currentcontrol is None:
			self.get_currentcontrol()
			
		transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
		bootkey_obf = ''
		for key in ['JD', 'Skew1', 'GBG', 'Data']:
			bootkey_obf += self.hive.get_class('%s\\Control\\Lsa\\%s' % (self.currentcontrol, key))
		
		bootkey_obf = bytes.fromhex(bootkey_obf)
		self.bootkey = b''
		for i in range(len(bootkey_obf)):
			self.bootkey += bootkey_obf[transforms[i]:transforms[i] + 1]
		
		return self.bootkey
		
class SAMSecret:
	def __init__(self):
		self.username
		self.rid
		self.nt_hash
		self.lm_hash
		

class SAM:
	def __init__(self, sam_hive, bootkey):
		self.hive = sam_hive
		self.bootkey = bootkey
		self.hashed_bootkey = None
		
	@staticmethod
	def rid_to_key(rid):
		key = int(rid, 16).to_bytes(4, 'little', signed = False)
		key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
		key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
		return expand_DES_key(bytes(key1)),expand_DES_key(bytes(key2))
		
	def decrypt_hash(self, rid, hashobj, constant):
		key1, key2 = SAM.rid_to_key(rid)
		des1 = des(key1)
		des2 = des(key2)
		
		if isinstance(hashobj, SAM_HASH):
			rc4key = hashlib.md5( self.hashed_bootkey[:0x10] + int(rid, 16).to_bytes(4, 'little', signed = False) + constant )
			key = RC4(rc4key).encrypt(hashobj.hash)
			
		else:
			key = b''
			cipher = AESModeOfOperationCBC(self.hashed_bootkey[:0x10], iv = hashobj.salt)
			n = 16
			for block in [hashobj.data[i:i+n] for i in range(0, len(hashobj.data), n)]:  #terrible, terrible workaround
				key += cipher.decrypt(block)
					
			key = key[:16]
			
		dec_hash = des1.decrypt(key[:8]) + des2.decrypt(key[8:])
		return dec_hash
		
	def get_HBoot_key(self):
		QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
		DIGITS = b"0123456789012345678901234567890123456789\0"
		
		F = self.hive.get_value(r'SAM\Domains\Account\F')[1]
		print(str(F))
		
		domain_properties = DOMAIN_ACCOUNT_F.from_bytes(F)
		
		#print(str(domain_properties))
		
		if isinstance(domain_properties.key_0, SAM_KEY_DATA):
			rc4_key = hashlib.md5(domain_properties.key_0.salt + QWERTY + self.bootkey +DIGITS).digest()
			self.hashed_bootkey = RC4(rc4_key).encrypt(domain_properties.key_0.key + domain_properties.key_0.checksum)
			
			checksum = hashlib.md5(self.hashed_bootkey[:16] + DIGITS + self.hashed_bootkey[:16] + QWERTY).digest()
			
			if checksum != self.hashed_bootkey[16:]:
				raise Exception('hashed_bootkey checksum failed!')
				
		elif isinstance(domain_properties.key_0, SAM_KEY_DATA_AES):
			self.hashed_bootkey = b''
			cipher = AESModeOfOperationCBC(self.bootkey, iv = domain_properties.key_0.salt)
			n = 16
			for block in [domain_properties.key_0.data[i:i+n] for i in range(0, len(domain_properties.key_0.data), n)]:  #terrible, terrible workaround
				self.hashed_bootkey += cipher.decrypt(block)
			
		print(self.hashed_bootkey.hex())
		return self.hashed_bootkey
		
	def dump(self):
		NTPASSWORD = b"NTPASSWORD\0"
		LMPASSWORD = b"LMPASSWORD\0"
		
		NTDEFAULT = '31d6cfe0d16ae931b73c59d7e0c089c0'
		LMDEFAULT = 'aad3b435b51404eeaad3b435b51404ee'
		
		self.get_HBoot_key()
		
		for rid in self.hive.enum_key('SAM\\Domains\\Account\\Users'):
			if rid == 'Names':
				continue
			
			uac_data = self.hive.get_value('SAM\\Domains\\Account\\Users\\%s\\V' % rid)[1]
			input('uac_data')
			uac = USER_ACCOUNT_V.from_bytes(uac_data)
			
			nthash = bytes.fromhex(NTDEFAULT)
			lmhash = bytes.fromhex(LMDEFAULT)
			if uac.NT_hash and isinstance(uac.NT_hash, SAM_HASH_AES):
				if uac.NT_hash.data != b'':
					nthash = self.decrypt_hash(rid, uac.NT_hash, NTPASSWORD)
			elif uac.NT_hash and isinstance(uac.NT_hash, SAM_HASH):
				if uac.NT_hash.hash != b'':
					nthash = self.decrypt_hash(rid, uac.NT_hash, NTPASSWORD)
			
			if uac.LM_hash and isinstance(uac.LM_hash, SAM_HASH_AES):
				if uac.LM_hash.data != b'':
					lmhash = self.decrypt_hash(rid, uac.LM_hash, LMPASSWORD)
			
			elif uac.NT_hash and isinstance(uac.NT_hash, SAM_HASH):
				if uac.NT_hash.hash != b'':
					nthash = self.decrypt_hash(rid, uac.NT_hash, NTPASSWORD)
					
			print('LM: %s' % lmhash)
			print('NT: %s' % nthash)
		
		
if __name__ == '__main__':
	
	bootkey = None
	with open('SYSTEM.reg', 'rb') as f:
		hive = AIOWinRegHive(f)
		system = SYSTEM(hive)
		bootkey = system.get_bootkey()
	
	with open('1_SAM.reg', 'rb') as f:
		hive = AIOWinRegHive(f)
		sam = SAM(hive, bootkey)
		sam.dump()
		
		