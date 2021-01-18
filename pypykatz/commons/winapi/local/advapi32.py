
import ctypes
from pypykatz.commons.winapi.constants import *
from pypykatz.commons.winapi.local.function_defs.advapi32 import RevertToSelf, LookupPrivilegeValueW, OpenProcessToken, GetTokenInformation_sid, LookupAccountSidW, ConvertSidToStringSidA, DuplicateTokenEx, CreateProcessWithTokenW, SetThreadToken, ConvertStringSidToSidA, LOGON_NETCREDENTIALS_ONLY
from pypykatz.commons.winapi.local.function_defs.kernel32 import STARTUPINFOW


class ADVAPI32:
	def __init__(self):
		pass
	
	@staticmethod
	def LookupPrivilegeValue(system_name, privilege_name):
		return LookupPrivilegeValueW(system_name, privilege_name)
		
	@staticmethod
	def OpenProcessToken(process_handle, DesiredAccess = TOKEN_ALL_ACCESS):
		return OpenProcessToken(process_handle, DesiredAccess = DesiredAccess)
		
	
	@staticmethod
	def GetTokenInformation_sid(token_handle):
		return GetTokenInformation_sid(token_handle)
		
	
	@staticmethod
	def LookupAccountSid(lpSystemName, lpSid):
		return LookupAccountSidW(lpSystemName, lpSid)
		
		
	@staticmethod
	def ConvertSidToStringSid(lpSid):
		return ConvertSidToStringSidA(lpSid)
		
	@staticmethod
	def ConvertStringSidToSid(StringSid):
		return ConvertStringSidToSidA(StringSid)

	@staticmethod
	def DuplicateTokenEx(hExistingToken, dwDesiredAccess = TOKEN_ALL_ACCESS, lpTokenAttributes = None, ImpersonationLevel = SecurityImpersonation, TokenType = TokenPrimary):
		return DuplicateTokenEx(hExistingToken, dwDesiredAccess = dwDesiredAccess, lpTokenAttributes = lpTokenAttributes, ImpersonationLevel = ImpersonationLevel, TokenType = TokenType)
		
		
	@staticmethod
	def CreateProcessWithToken_manip(token, cmdline):
		SW_SHOW = 5
		STARTF_USESHOWWINDOW = 0x00000001
		
		lpStartupInfo			  = STARTUPINFOW()
		lpStartupInfo.cb		   = ctypes.sizeof(STARTUPINFOW)
		lpStartupInfo.lpReserved   = 0
		lpStartupInfo.lpDesktop	= 0
		lpStartupInfo.lpTitle	  = 0
		lpStartupInfo.dwFlags	  = STARTF_USESHOWWINDOW
		lpStartupInfo.cbReserved2  = 0
		lpStartupInfo.lpReserved2  = 0
		lpStartupInfo.wShowWindow  = SW_SHOW
		
		
		CREATE_NEW_CONSOLE        = 0x00000010
		CreateProcessWithTokenW(
			hToken = token, 
			dwLogonFlags = LOGON_NETCREDENTIALS_ONLY, 
			lpApplicationName = None, 
			lpCommandLine = cmdline, 
			dwCreationFlags = CREATE_NEW_CONSOLE, 
			lpEnvironment = None, 
			lpCurrentDirectory = None, 
			lpStartupInfo = lpStartupInfo
		)
		
		
	@staticmethod
	def SetThreadToken(token_handle, thread_handle = None):
		return SetThreadToken(token_handle, thread_handle = thread_handle)
	
	@staticmethod
	def RevertToSelf():
		return RevertToSelf()
		