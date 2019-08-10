import os

from pypykatz import logger
from pypykatz.dpapi.structures.masterkeyfile import MasterKeyFile
from pypykatz.dpapi.structures.credentialfile import CredentialFile
from pypykatz.dpapi.structures.blob import DPAPI_BLOB

import hmac
import hashlib
from hashlib import sha1, pbkdf2_hmac

"""
So! DPAPI...

In order to decrpyt a file/blob/data of any kind you must obtain a masterkey.
Masterkey can be obtained either from the LSASS process, or by decrypting a masterkeyfile. LSASS is straightforward, succsessfully dumping it will give you all the plaintext masterkeys with the appropriate GUID.
 But if you can't use LSASS, you have to obtain the masterkey file, and decrypt it with an appropriate key. (too many keys, I know...)
 Masterkey files can be located in '%APPDATA%\Microsoft\Protect\%SID%' for each user or '%SYSTEMDIR%\Microsoft\Protect' for the SYSTEM user. But how to decrypt them?
 A masterkeyfile can contain multiple different keys, a masterkey is one of them. The masterkey is stored encrypted in the masterkeyfile, and is encrypted with a key that can be either a key stored in registry (LSA secrets) or not. In case the LSA DPAPI keys are not valid, you will need to use the NT hash of the user's password or the user's plaintext password itself. BUT! deriving the key from the password and the SID will yield 3 different keys, and so far noone could tell what key is the correct one to be used.
 Solution for decrypting a masterkey in the mastereky file: harvest as many key candidates as possible and try to decrypt the masterkey. Much to our luck, verifying the signature data after decryption can tell us if the decrpytion was sucsessfull, so we can tell if the masterkey decrypted correctly or not.

But you may ask: I see a lot of different masterkey files, how can I tell which one is used for my <credential file/vault files/blob>. The answer: a masterkeyfile stores GUID of the keys it stores (eg. the masterkey), and so does your <secret> data sructure for the appropriate key. Therefore it's easy to tell which file to decrypt for a given <secret>

"""

class DPAPIUserKey:
	def __init__(self):
		self.dunno = None
	
	def from_registry(self):
		pass
		
	def from_password(self):
		pass
		
	def from_lsa(self):
		pass
		
class DPAPIKey:
	def __init__(self):
		self.sid = None
		self.password = None
		self.password = None
	
	def from_registry(self):
		pass
		
	def from_password(self):
		pass
		
	def from_lsa(self):
		pass


class DPAPI:
	def __init__(self):
		self.user_keys = []
		self.machine_keys = []
		
		self.masterkeys = {} #guid -> binary value
	
	@staticmethod
	def list_masterkeys():
		#logger.debug('Searching for MasterKey files...')
		#appdata = os.environ.get('APPDATA')
		#'%APPDATA%\Microsoft\Protect\%SID%'
		#'%SYSTEMDIR%\Microsoft\Protect'
		# TODO: implement this
		pass
		
	def get_keys_from_password(self, sid, password = None, nt_hash = None):
		"""
		Resulting keys used to decrypt the masterkey
		"""
		if password is None and nt_hash is None:
			raise Exception('Provide either password or NT hash!')
		
		if password is None and nt_hash:
			key1 = None
		
		if password:
			md4 = hashlib.new('md4')
			md4.update(password.encode('utf-16le'))
			nt_hash = md4.digest()
			# Will generate two keys, one with SHA1 and another with MD4
			key1 = hmac.new(sha1(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), sha1).digest()
		
		key2 = hmac.new(nt_hash, (sid + '\0').encode('utf-16le'), sha1).digest()
		# For Protected users
		tmp_key = pbkdf2_hmac('sha256', nt_hash, sid.encode('utf-16le'), 10000)
		tmp_key_2 = pbkdf2_hmac('sha256', tmp_key, sid.encode('utf-16le'), 1)[:16]
		key3 = hmac.new(tmp_key_2, (sid + '\0').encode('utf-16le'), sha1).digest()[:20]
		
		if key1 is not None:
			self.user_keys.append(key1)
		self.user_keys.append(key2)
		self.user_keys.append(key3)
		
		return key1, key2, key3
		
	def get_masterkeys_from_lsass(self):
		"""
		Returns the plaintext final masterkeys! No need to decrpyt and stuff!
		"""
		from pypykatz.pypykatz import pypykatz
		katz = pypykatz.go_live()
		for x in katz.logon_sessions:
			for dc in katz.logon_sessions[x].dpapi_creds:
				self.masterkeys[dc.key_guid] = bytes.fromhex(dc.masterkey)
				
	def __get_registry_secrets(self, lr):
		from pypykatz.registry.security.common import LSASecretDPAPI
		for secret in lr.security.cached_secrets:
			if isinstance(secret, LSASecretDPAPI):
				print('Found DPAPI key in registry!')
				print(secret.user_key)
				print(secret.machine_key)
				self.user_keys.append(secret.user_key)
				self.machine_keys.append(secret.machine_key)
		
		if lr.sam is not None:
			for secret in lr.sam.secrets:
				if secret.nt_hash:
					#TODO: figure out how to get machine sid, then enable this...
					#sid = '%s-%s' % (lr.sam.machine_sid, secret.rid)
					#self.get_keys_from_password(sid, nt_hash = secret.nt_hash)
					continue
	
	def get_keys_form_registry_live(self):
		from pypykatz.registry.live_parser import LiveRegistry
		from pypykatz.registry.offline_parser import OffineRegistry
		lr = None
		try:
			lr = LiveRegistry.go_live()
		except Exception as e:
			logger.debug('Failed to obtain registry secrets via direct registry reading method')
			try:
				lr = OffineRegistry.from_live_system()
			except Exception as e:
				logger.debug('Failed to obtain registry secrets via filedump method')
		
		if lr is not None:
			self.__get_registry_secrets(lr)

		else:
			raise Exception('Registry parsing failed!')
			
	def get_keys_form_registry_files(self, system_path, security_path, sam_path = None):
		from pypykatz.registry.offline_parser import OffineRegistry
		lr = None
		try:
			lr = OffineRegistry.from_files(system_path, sam_path = sam_path, security_path = security_path)
		except Exception as e:
			logger.error('Failed to obtain registry secrets via direct registry reading method. Reason: %s' %e)
		
		if lr is not None:
			self.__get_registry_secrets(lr)

		else:
			raise Exception('Registry parsing failed!')
	
	def decrypt_masterkey(self, data):
		mkf = MasterKeyFile.from_bytes(data)
		
		if mkf.masterkey is not None:
			for user_key in self.user_keys:
				dec_key = mkf.masterkey.decrypt(user_key)
				if dec_key:
					print(dec_key)
				else:
					print('Fail')
			for machine_key in self.machine_keys:
				dec_key = mkf.masterkey.decrypt(machine_key)
				if dec_key:
					print(dec_key)
				else:
					print('Fail')
				
	def decrypt_credential(self, data):
		cred = CredentialFile.from_bytes(data)
		return cred.blob.decrypt(key)
		
	def decrypt_blob(self, data):
		blob = DPAPI_BLOB.from_bytes(data)
		if blob.masterkey_guid not in self.masterkeys:
			raise Exception('No matching masterkey was found for the blob!')
		key = self.masterkeys[blob.masterkey_guid]
		print(str(blob))
		return blob.decrypt(key)
	
	
	
if __name__ == '__main__':
	filename = 'C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-3448413973-1765323015-1500960949-1105\\4c9764dc-aa99-436c-bb30-ff39b3dd407c'
	dpapi = DPAPI()
	#dpapi.get_keys_form_registry_live()
	dpapi.get_keys_form_registry_files('SYSTEM.reg', 'SECURITY.reg',  '1_SAM.reg')
	
	
	#nt_hash = hashlib.new('md4')
	#nt_hash.update('Passw0rd!1'.encode('utf-16-le'))
	#dpapi.get_keys_from_password('S-1-5-21-3448413973-1765323015-1500960949-1105', nt_hash = nt_hash.digest())
	with open(filename, 'rb') as f:
		dpapi.decrypt_masterkey(f.read())
	
	#data = bytes.fromhex('01000000d08c9ddf0115d1118c7a00c04fc297eb01000000dc64974c99aa6c43bb30ff39b3dd407c0000000002000000000003660000c000000010000000f1af675a51c8283cf81abb6fb600110f0000000004800000a0000000100000009bf4e56d6c32dd59bce655496a94444c1000000088438c8f61d966ac220b4ca50933c8ee14000000314eaa780e358e70c586fb47bee0e27549be480e')
	#dpapi.decrypt_blob(data)