#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
from pypykatz.registry import logger
from pypykatz.commons.common import hexdump

#
# The SYSTEM hive holds the BootKey, which is used as an initial key to decrypt everything in the registry.
# Without having the BootKey no decryption can be performed on any of the secrets, 
# therefore it is mandatory to supply this hive.
#
# The way to obtain the BootKey is quite straightforward.
# First, we need to determine the current controlset (when the machine is running you find that available directly, but not when the hive was taken from a powered down machine)
# Second, the BootKey is obfuscated and scattered in the Class attribute of 4 different registry keys.
#         we read the Class attribute of these keys and de-obfuscate the key
#

class SYSTEM:
	def __init__(self, system_hive):
		self.hive = system_hive
		self.currentcontrol = None
		self.bootkey = None
		self.machinename = None
		
	def get_currentcontrol(self):
		logger.debug('[SYSTEM] determining current control set')
		if self.currentcontrol is not None:
			return self.currentcontrol
			
		ccs = self.hive.get_value('Select\\Current')[1]
		self.currentcontrol = "ControlSet%03d" % ccs
		logger.debug('[SYSTEM] current control set name: %s' % self.currentcontrol)
		return self.currentcontrol
		
	def get_bootkey(self):
		logger.debug('[SYSTEM] get_bootkey invoked')
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
		
		logger.debug('[SYSTEM] bootkey: %s' % self.bootkey.hex())
		return self.bootkey
		
	def get_secrets(self):
		self.get_currentcontrol()
		self.get_bootkey()
		self.get_machine_name()

	def get_service_user(self, service_name):
		if self.currentcontrol is None:
			self.get_currentcontrol()
		
		try:
			key = '%s\\Services\\%s\\ObjectName' % (self.currentcontrol, service_name)
			val = self.hive.get_value(key)[1]
			val = val.decode('utf-16-le')
			val = val.replace('\x00', '')
			return val
		except:
			return None
	
	def get_machine_name(self):
		if self.currentcontrol is None:
			self.get_currentcontrol()
		
		try:
			if self.machinename is not None:
				return self.machinename
			
			key = '%s\\Control\\ComputerName\\ComputerName\\ComputerName' % self.currentcontrol
			val = self.hive.get_value(key)
			if isinstance(val[1], bytes):
				self.machinename = val[1].decode('utf-16-le')
			else:
				self.machinename = val[1]
			if self.machinename is not None:
				self.machinename = self.machinename.replace('\x00', '')
			return self.machinename
		except Exception as e:
			print('[SYSTEM] get_machine_name error: %s' % e)
			return None

	def to_dict(self):
		t = {}
		t['CurrentControlSet'] = self.currentcontrol
		t['BootKey'] = self.bootkey
		return t
		
	def __str__(self):
		t  = '============== SYSTEM hive secrets ==============\r\n'
		t += 'CurrentControlSet: %s\r\n' % self.currentcontrol
		t += 'Boot Key: %s\r\n' % self.bootkey.hex()
		return t
