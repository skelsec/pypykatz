
from pypykatz.commons.winapi.local.ntdll import NTDLL
from pypykatz.commons.winapi.local.advapi32 import ADVAPI32
from pypykatz.commons.winapi.local.psapi import PSAPI
from pypykatz.commons.winapi.local.kernel32 import KERNEL32

class LocalWindowsAPI:
	def __init__(self):
		self.ntdll = NTDLL
		self.advapi32 = ADVAPI32
		self.psapi = PSAPI
		self.kernel32 = KERNEL32