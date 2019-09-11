#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import json
from aiowinreg.hive import AIOWinRegHive

from pypykatz.registry import logger
from pypykatz.commons.common import UniversalEncoder
from pypykatz.registry.sam.sam import *
from pypykatz.registry.security.security import *
from pypykatz.registry.system.system import *
from pypykatz.registry.software.software import *


class OffineRegistry:
	"""
	This class represents an offline registry
	You will need to set at least the SYSTEM hive (to get bootkey)
	In case you have the SAM and/or SECURITY hives, it will parse them for the stored credentials/secrets as well.
	"""
	def __init__(self):		
		self.sam_hive = None
		self.security_hive = None
		self.system_hive = None
		self.software_hive = None
		
		self.system = None
		self.sam = None
		self.security = None
		self.software = None
		
	def get_secrets(self):
		self.system = SYSTEM(self.system_hive)
		bootkey = self.system.get_bootkey()
		
		if self.sam_hive:
			self.sam = SAM(self.sam_hive, bootkey)
			self.sam.get_secrets()
			
		if self.security_hive:
			self.security = SECURITY(self.security_hive, bootkey)
			self.security.get_secrets()
			
		if self.software_hive:
			self.software = SOFTWARE(self.software_hive, bootkey)
			self.software.get_default_logon()
			
		self.cleanup()
		
	def cleanup(self):
		for hive in [self.system_hive, self.security_hive, self.sam_hive]:
			try:
				hive.close()
			except:
				pass
		
	def to_file(self, file_path, json_format = False):
		with open(file_path, 'w', newline = '') as f:
			if json_format == False:
				f.write(str(self))
			else:
				f.write(self.to_json())
	
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True)
			
	def to_dict(self):
		t = {}
		t['SYSTEM'] = self.system.to_dict()
		if self.sam:
			t['SAM'] = self.sam.to_dict()
		if self.security:
			t['SECURITY'] = self.security.to_dict()
		if self.software:
			t['SOFTWARE'] = self.software.to_dict()
		return t
		
		
	def __str__(self):
		t = str(self.system)
		if self.sam:
			t += str(self.sam)
		if self.security:
			t += str(self.security)
		if self.software:
			t += str(self.software)
		return t

	@staticmethod
	def from_bytes(system_data, sam_data = None, security_data = None, software_data = None):
		system_buff = io.BytesIO(system_data)
		sam_buff = None
		security_buff = None
		software_buff = None

		if sam_data:
			sam_buff  = io.BytesIO(sam_data)
		if security_data:
			security_buff = io.BytesIO(security_data)
		if software_data:
			software_buff = io.BytesIO(software_data)

		return OffineRegistry.from_buffer(system_buff, sam_buff = sam_buff, security_buff = security_buff, software_buff = software_buff)

	@staticmethod
	def from_buffer(system_buff, sam_buff = None, security_buff = None, software_buff = None):
		return OffineRegistry.from_files(system_buff, sam_path = sam_buff, security_path = security_buff, software_path = software_buff, notfile = True)
		
	@staticmethod
	def from_files(system_path, sam_path = None, security_path = None, software_path = None, notfile = False):
		po = OffineRegistry()
		
		try:
			if notfile == True:
				sys_hive = system_path
			else:
				sys_hive = open(system_path, 'rb')
			po.system_hive = AIOWinRegHive(sys_hive)
		except Exception as e:
			logger.error('Failed to open SYSTEM hive! Reason: %s' % str(e))
			raise e
		
		if sam_path:
			try:
				if notfile == True:
					sam_hive = sam_path
				else:
					sam_hive = open(sam_path, 'rb')

				po.sam_hive = AIOWinRegHive(sam_hive)
			except Exception as e:
				logger.error('Failed to open SAM hive! Reason: %s' % str(e))
				raise e
				
		else:
			logger.warning('SAM hive path not supplied! Parsing SAM will not work')
			
		if security_path:
			try:
				if notfile == True:
					sec_hive = security_path
				else:
					sec_hive = open(security_path, 'rb')				
				po.security_hive = AIOWinRegHive(sec_hive)
			except Exception as e:
				logger.error('Failed to open SECURITY hive! Reason: %s' % str(e))
				raise e
				
		else:
			logger.warning('SECURITY hive path not supplied! Parsing SECURITY will not work')
			
		if software_path:
			try:
				if notfile == True:
					sof_hive = software_path
				else:
					sof_hive = open(software_path, 'rb')
				
				po.software_hive = AIOWinRegHive(sof_hive)
			except Exception as e:
				logger.error('Failed to open SECURITY hive! Reason: %s' % str(e))
				raise e
				
		else:
			logger.warning('SOFTWARE hive path not supplied! Parsing SOFTWARE will not work')
		
		
		po.get_secrets()
		try:
			sec_hive.close()
		except:
			pass
		try:
			sam_hive.close()
		except:
			pass
		try:
			sys_hive.close()
		except:
			pass
		try:
			sof_hive.close()
		except:
			pass
		
		return po
	
	@staticmethod
	def from_live_system():
		logger.debug('Obtaining registry from local system')
		try:
			from pypykatz.commons.winapi.processmanipulator import ProcessManipulator
			from pypykatz.commons.winapi.constants import SE_BACKUP
			import winreg
			import tempfile
			import os
			import ntpath
		except Exception as e:
			logger.error('Could not import necessary packages! Are you on Windows? Error: %s' % str(e))
			raise
			
		sam_name = ntpath.join(tempfile.gettempdir(), os.urandom(4).hex())
		system_name = ntpath.join(tempfile.gettempdir(), os.urandom(4).hex())
		security_name = ntpath.join(tempfile.gettempdir(), os.urandom(4).hex())
		
		locations = [
			('SAM', sam_name),
			('SYSTEM', system_name),
			('SECURITY', security_name),
		]
		
		logger.debug('Obtaining SE_BACKUP privilege...')
		try:
			po = ProcessManipulator()
			po.set_privilege(SE_BACKUP)
		except Exception as e:
			logger.error('Failed to obtain SE_BACKUP privilege! Registry dump will not work! Reason: %s' % str(e))
			raise e
		logger.debug('Obtaining SE_BACKUP OK!')
		
		dumped_names = {}
		for reg_name, location in locations:
			logger.debug('Dumping %s...' % reg_name)
			try:
				key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_name, access=0x00020000)
				winreg.SaveKey(key, location)
				key.Close()
			except Exception as e:
				logger.error('Dumping %s FAILED!! Reason: %s' % (reg_name, str(e)))
			else:
				logger.debug('Dumping %s OK!' % reg_name)
				dumped_names[reg_name] = location
		###
		### Do Parsing here!
		###
		po = None
		if 'SYSTEM' in dumped_names:
			try:
				po = OffineRegistry.from_files(system_name, sam_name if 'SAM' in dumped_names else None, security_name if 'SECURITY' in dumped_names else None)
			except Exception as e:
				import traceback
				traceback.print_exc()
		else:
			logger.error('Failed to dump SYSTEM hive, exiting...')
			
		logger.debug('Cleaning up temp files')
		for reg_name, location in locations:
			try:
				os.remove(location)
			except Exception as e:
				logger.error('Failed to clean up temp file for %s! Sensitive files might have been left on the filesystem! Path: %s Reason: %s' % (reg_name, location, str(e)))
			else:
				logger.debug('Cleanup for %s OK!' % reg_name)
	
		return po
	
if __name__ == '__main__':
	po = OffineRegistry.from_live_system()
	print(str(po))