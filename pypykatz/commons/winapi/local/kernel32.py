from pypykatz.commons.winapi.local.function_defs.kernel32 import OpenProcess, CloseHandle, GetCurrentProcessId


class KERNEL32:
	def __init__(self):
		pass
	
	@staticmethod
	def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
		return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
		
	@staticmethod
	def CloseHandle(any_handle):
		CloseHandle(any_handle)
		
	@staticmethod
	def GetCurrentProcessId():
		return GetCurrentProcessId()