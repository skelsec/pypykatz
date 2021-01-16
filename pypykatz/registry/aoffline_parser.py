#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import json
from aiowinreg.ahive import AIOWinRegHive

from pypykatz.registry import logger
from pypykatz.commons.common import UniversalEncoder
from pypykatz.registry.sam.asam import *
from pypykatz.registry.security.asecurity import *
from pypykatz.registry.system.asystem import *
from pypykatz.registry.software.asoftware import *


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
		
	async def get_secrets(self):
		self.system = SYSTEM(self.system_hive)
		bootkey = await self.system.get_bootkey()
		
		if self.sam_hive:
			self.sam = SAM(self.sam_hive, bootkey)
			await self.sam.get_secrets()
			
		if self.security_hive:
			self.security = SECURITY(self.security_hive, bootkey)
			await self.security.get_secrets()
			
		if self.software_hive:
			self.software = SOFTWARE(self.software_hive, bootkey)
			await self.software.get_default_logon()
		
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
	async def from_async_reader(system_reader, sam_reader = None, security_reader = None, software_reader = None):
		po = OffineRegistry()
		po.system_hive = AIOWinRegHive(system_reader)
		await po.system_hive.setup()
		
		if sam_reader is not None:
			po.sam_hive = AIOWinRegHive(sam_reader)
			await po.sam_hive.setup()
		
		if security_reader is not None:
			po.security_hive = AIOWinRegHive(security_reader)
			await po.security_hive.setup()
		
		if software_reader is not None:
			po.software_hive = AIOWinRegHive(software_reader)
			await po.software_hive.setup()
		
		await po.get_secrets()

		return po

	
	
if __name__ == '__main__':
	po = OffineRegistry.from_live_system()
	print(str(po))