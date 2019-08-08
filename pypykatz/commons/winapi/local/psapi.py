from pypykatz.commons.winapi.local.function_defs.psapi import EnumProcesses


class PSAPI:
	def __init__(self):
		pass
	
	@staticmethod
	def EnumProcesses():
		return EnumProcesses()
		