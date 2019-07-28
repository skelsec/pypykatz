
import hashlib
import hmac
from pypykatz.lsa.sam.structures import *
from pypykatz.crypto.RC4 import RC4
from pypykatz.crypto.aes import AESModeOfOperationCBC,AESModeOfOperationECB, Decrypter
from pypykatz.crypto.des import *

#####
import aiowinreg
from aiowinreg.hive import AIOWinRegHive


#####
from pypykatz.lsa.security.structures import *


class SECURITY:
	def __init__(self, security_hive, bootkey):
		self.hive = security_hive
		self.bootkey = bootkey
		
		self.dcc_iteration_count = 10240
		self.lsa_secret_key_vista_type = True
		
		self.lsa_key = None
		self.NKLM_key = None
	
	@staticmethod
	def sha256_multi(key, value, rounds = 1000):
		ctx = hashlib.sha256(key)
		for i in range(rounds):
			ctx.update(value)
		return ctx.digest()
		
	def decrypt_lsa_key(self, data):
		if self.lsa_secret_key_vista_type is True:
			record = LSA_SECRET.from_bytes(data)
			key = SECURITY.sha256_multi(self.bootkey, record.data[:32])
			secret_dec = b''
			cipher = AESModeOfOperationECB(key)
			n = 16
			for block in [record.data[32:][i:i+n] for i in range(0, len(record.data[32:]), n)]:  #terrible, terrible workaround
				secret_dec += cipher.decrypt(block)
			record = LSA_SECRET_BLOB.from_bytes(secret_dec)
			self.lsa_key = record.secret[52:][:32]
		
		else:
			ctx = hashlib.md5(self.bootkey)
			for i in range(1000):
				ctx.update(value[60:76])
			
			cipher = RC4.new(ctx.digest())
			record = rc4.decrypt(value[12:60])
			self.lsa_key = record[0x10:0x20]
		
		return self.lsa_key
			
		
	def get_lsa_key(self):
		value = self.hive.get_value('Policy\\PolEKList\\default')
		if value is None:
			value = self.hive.get_value('Policy\\PolSecretEncryptionKey\\default')
			if not value:
				return None
			
			self.lsa_secret_key_vista_type = False
			
		return self.decrypt_lsa_key(value[1])
		
		
	def decrypt_secret(self, key, value):
		pass
		
	def get_NKLM_key(self):
		if self.lsa_key is None:
			self.get_lsa_secret_key()
			
		value = self.hive.get_value('Policy\\Secrets\\NL$KM\\CurrVal\\default')
		if value is None:
			raise Exception('Could not find NL$KM in registry :(')
			
		if self.lsa_secret_key_vista_type is True:
			self.NKLM_key = b''
			record = LSA_SECRET.from_bytes(value[1])
			key = SECURITY.sha256_multi(self.lsa_key, record.data[:32])
			cipher = AESModeOfOperationECB(key)
			n = 16
			for block in [record.data[32:][i:i+n] for i in range(0, len(record.data[32:]), n)]:  #terrible, terrible workaround
				self.NKLM_key += cipher.decrypt(block)
			
		else:
			self.NKLM_key = self.decrypt_secret(self.lsa_key, value[1])
			
		return self.NKLM_key
		
	def __pad(self, data):
		if (data & 0x3) > 0:
			return data + (data & 0x3)
		else:
			return data
		
	def dump_dcc(self):
		cache_reg = self.hive.find_key('Cache')
		values = self.hive.list_values(cache_reg)
		if values == []:
			return
			
		if b'NL$Control' in values:
			values.remove(b'NL$Control')
			
		if b'NL$IterationCount' in values:
			values.remove(b'NL$IterationCount')
			record = self.getValue('Cache\\NL$IterationCount')[1]
			if record > 10240:
				self.dcc_iteration_count = record & 0xfffffc00
			else:
				self.dcc_iteration_count = record * 1024
				
		
		self.get_lsa_key()
		self.get_NKLM_key()
		
		print(self.lsa_key)
		print(self.NKLM_key)
		
		for value in values:
			print('Checking value: %s' % value)
			record_data = self.hive.get_value('Cache\\%s' % value.decode())[1]
			record = NL_RECORD.from_bytes(record_data)
			
			if record.IV != b'\x00'*16:
				if record.Flags & 1 == 1:
					# Encrypted
					if self.lsa_secret_key_vista_type is True:
						plaintext = b''
						cipher = AESModeOfOperationCBC(self.NKLM_key[16:32], iv = record.IV)
						n = 16
						for block in [record.EncryptedData[i:i+n] for i in range(0, len(record.EncryptedData), n)]:  #terrible, terrible workaround
							if len(block) < 16:
								block += b'\x00' * (16 - len(block))
							plaintext += cipher.decrypt(block)
							
					else:
						key = hmac.new(self.NKLM_key,record.IV).digest()
						cipher = RC4(key)
						plaintext = cipher.decrypt(record.EncryptedData)
						
				else:
					# Plain! Until we figure out what this is, we skip it
					#plainText = record['EncryptedData']
					continue
				
				
				dcc_hash = plaintext[:0x10]
				blob = io.BytesIO(plaintext[0x48:])
				username = blob.read(record.UserLength).decode('utf-16-le')
				blob.seek(self.__pad(record.UserLength) + self.__pad(record.DomainNameLength))
				domain = blob.read(record.DnsDomainNameLength).decode('utf-16-le')
				
				if self.lsa_secret_key_vista_type is True:
					ans = "%s/%s:$DCC2$%s#%s#%s" % (domain, username, self.dcc_iteration_count, username, dcc_hash.hex())
				else:
					ans = "%s/%s:%s:%s" % (domain, username, dcc_hash.hex(), username)
					
				print(ans)
				
	def dump_secrets(self):
		self.get_lsa_key()
		self.get_NKLM_key()
		
		# Let's first see if there are cached entries
		keys = self.hive.enum_key('Policy\\Secrets')
		if keys is None:
			# No entries
			return
			
		if b'NL$Control' in keys:
			keys.remove(b'NL$Control')
		
		for key_name in keys:
			for vl in ['CurrVal', 'OldVal']:
				key_path = 'Policy\\Secrets\\{}\\{}\\default'.format(key_name,vl)
				print(key_path)
				v = self.hive.get_value(key_path)
				if v and v[1] != 0:
					if self.lsa_secret_key_vista_type is True:
						record = LSA_SECRET.from_bytes(v[1])
						key = SECURITY.sha256_multi(self.lsa_key, record.data[:32])
						secret_dec = b''
						cipher = AESModeOfOperationECB(key)
						n = 16
						for block in [record.data[32:][i:i+n] for i in range(0, len(record.data[32:]), n)]:  #terrible, terrible workaround
							secret_dec += cipher.decrypt(block)
						record = LSA_SECRET_BLOB.from_bytes(secret_dec)
						secret = record.secret
					else:
						raise NotImplementedError('TODO')
				
				print(secret)
						

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
	def __init__(self, username, rid, nt_hash, lm_hash):
		self.username = username
		self.rid = rid
		self.nt_hash = nt_hash
		self.lm_hash = lm_hash
		
	def to_dict(self):
		return {
			'username' : username,
			'rid' : self.rid,
			'nt_hash' : self.nt_hash,
			'lm_hash' : self.lm_hash,
		}
		
	def to_json(self):
		return json.dumps(self.to_dict())
	
	def to_lopth(self):
		return '%s:%s:%s:%s:::' % (self.username, self.rid, self.lm_hash.hex(), self.nt_hash.hex())
		
		

class SAM:
	def __init__(self, sam_hive, bootkey):
		self.hive = sam_hive
		self.bootkey = bootkey
		self.hashed_bootkey = None
		self.secrets = []
		
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
			
			secret = SAMSecret(uac.name, int(rid,16), nthash, lmhash)
			print(secret.to_lopth())
			self.secrets.append(secret)
			
		return self.secrets
		
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
		
	with open('SECURITY.reg', 'rb') as f:
		hive = AIOWinRegHive(f)
		sam = SECURITY(hive, bootkey)
		sam.dump_dcc()
		sam.dump_secrets()
		
		