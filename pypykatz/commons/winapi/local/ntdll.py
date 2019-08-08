
from pypykatz.commons.winapi.local.function_defs.ntdll import RtlAdjustPrivilege


class NTDLL:
	def __init__(self):
		pass
	
	@staticmethod
	def RtlAdjustPrivilege(privilige_id, enable = True, thread_or_process = False):
		return RtlAdjustPrivilege(privilige_id, enable = True, thread_or_process = False)