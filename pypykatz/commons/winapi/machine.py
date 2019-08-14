#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import platform
from pypykatz import logger
import winreg

from pypykatz.commons.winapi.local.localwindowsapi import LocalWindowsAPI
from pypykatz.commons.winapi.constants import *
from pypykatz.commons.readers.registry.live.reader import LiveRegistryHive

class User:
	def __init__(self, name, domain, sid):
		self.username = name
		self.domain = domain
		self.sid = sid
		
	def __str__(self):
		return '%s:%s:%s' % (str(self.domain), str(self.username), str(self.sid))

class LiveMachine:
	"""
	
	"""
	def __init__(self, api = None):
		self.api = api if api is not None else LocalWindowsAPI()
		self.domain = None
		self.hostname = None
		
	def get_hostname(self):
		if self.hostname is None:
			params = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters')
			self.hostname = winreg.QueryValueEx(params, 'NV Hostname')[0]
		return self.hostname
		
	def get_domain(self):
		if self.domain is None:
			params = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters')
			self.domain = winreg.QueryValueEx(params, 'Domain')[0]
		return self.domain
		
	def get_current_user(self):
		pid = self.api.kernel32.GetCurrentProcessId()
		proc_handle = self.api.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
		token_handle = self.api.advapi32.OpenProcessToken(proc_handle, TOKEN_MANIP_ACCESS)
		ptr_sid = self.api.advapi32.GetTokenInformation_sid(token_handle)
		sid_str = self.api.advapi32.ConvertSidToStringSid(ptr_sid)
		name, domain, token_type = self.api.advapi32.LookupAccountSid(None, ptr_sid)
		return User(name, domain, sid_str)
		
	def list_users(self):
		logger.debug('Listing SIDs from registry...')
		software_hive = LiveRegistryHive('SOFTWARE')
		users = {}
		for sid_str in software_hive.enum_key('Microsoft\\Windows NT\\CurrentVersion\\ProfileList'):
			if sid_str.endswith('_Classes') or sid_str.startswith('.'):
				continue
			ptr_sid = self.api.advapi32.ConvertStringSidToSid(sid_str.encode())
			name, domain, token_type = self.api.advapi32.LookupAccountSid(None, ptr_sid)
			users[sid_str] = User(name, domain, sid_str)
		return users
			
if __name__ == '__main__':
	u = LiveMachine()
	t = u.list_users()
	for sid in t:
		print(str(t[sid]))
	t = u.get_current_user()
	print(str(t))