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
		
	async def get_currentcontrol(self):
		logger.debug('[SYSTEM] determining current control set')
		if self.currentcontrol is not None:
			return self.currentcontrol
			
		ccs = await self.hive.get_value('Select\\Current')
		ccs = ccs[1]
		self.currentcontrol = "ControlSet%03d" % ccs
		logger.debug('[SYSTEM] current control set name: %s' % self.currentcontrol)
		return self.currentcontrol
		
	async def get_bootkey(self):
		logger.debug('[SYSTEM] get_bootkey invoked')
		if self.bootkey is not None:
			return self.bootkey
		if self.currentcontrol is None:
			await self.get_currentcontrol()
			
		transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
		bootkey_obf = ''
		for key in ['JD', 'Skew1', 'GBG', 'Data']:
			bootkey_obf += await self.hive.get_class('%s\\Control\\Lsa\\%s' % (self.currentcontrol, key))
		
		bootkey_obf = bytes.fromhex(bootkey_obf)
		self.bootkey = b''
		for i in range(len(bootkey_obf)):
			self.bootkey += bootkey_obf[transforms[i]:transforms[i] + 1]
		
		logger.debug('[SYSTEM] bootkey: %s' % self.bootkey.hex())
		return self.bootkey
		
	async def get_secrets(self):
		await self.get_currentcontrol()
		await self.get_bootkey()
	
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
