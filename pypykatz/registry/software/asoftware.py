#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

#####
from pypykatz.registry import logger


class SOFTWARE:
	def __init__(self, sam_hive, bootkey):
		self.hive = sam_hive
		self.bootkey = bootkey
		self.default_logon_user = None
		self.default_logon_domain = None
		self.default_logon_password = None
		
	async def get_default_logon(self):
		if self.default_logon_user is None:
			try:
				data = await self.hive.get_value(r'Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultUserName')
				data = data[1]
			except:
				pass
			else:
				if isinstance(data, bytes):
					self.default_logon_user = data.decode('utf-16-le').split('\x00')[0]
				else:
					self.default_logon_user = data
		
		if self.default_logon_domain is None:
			try:
				data = await self.hive.get_value(r'Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultDomainName')
				data = data[1]
			except:
				pass
			else:
				if isinstance(data, bytes):
					self.default_logon_domain = data.decode('utf-16-le')
				else:
					self.default_logon_domain = data
		
		if self.default_logon_password is None:
			try:
				data = await self.hive.get_value(r'Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword')
				data = data[1]
			except:
				pass
			else:
				if isinstance(data, bytes):
					self.default_logon_password = data.decode('utf-16-le')
				else:
					self.default_logon_password = data

		if isinstance(self.default_logon_password, str):
			self.default_logon_password = self.default_logon_password.replace('\x00', '')
		if isinstance(self.default_logon_user, str):
			self.default_logon_user = self.default_logon_user.replace('\x00', '')
		if isinstance(self.default_logon_domain, str):
			self.default_logon_domain = self.default_logon_domain.replace('\x00', '')
				
		return self.default_logon_user
		
	def to_dict(self):
		t = {}
		t['default_logon_user'] = self.default_logon_user
		t['default_logon_domain'] = self.default_logon_domain
		t['default_logon_password'] = self.default_logon_password
		return t
		
	def __str__(self):
		t  = '============== SOFTWARE hive secrets ==============\r\n'
		t += 'default_logon_user: %s\r\n' % self.default_logon_user
		t += 'default_logon_domain: %s\r\n' % self.default_logon_domain
		t += 'default_logon_password: %s\r\n' % self.default_logon_password
		return t
