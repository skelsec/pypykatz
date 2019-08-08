
import ctypes
from ctypes import windll
from ctypes.wintypes import ULONG, BOOL,LONG

from .defines import *

# https://source.winehq.org/WineAPI/RtlAdjustPrivilege.html
# BOOL WINAPI RtlAdjustPrivilege(
#   __in   ULONG     Privilege,
#   __in   BOOLEAN   Enable,
#   __in   BOOLEAN   CurrentThread,
#   __in   PBOOLEAN  Enabled,
# );
def RtlAdjustPrivilege(privilige_id, enable = True, thread_or_process = False):
	"""
	privilige_id: int
	"""
	_RtlAdjustPrivilege = windll.ntdll.RtlAdjustPrivilege
	_RtlAdjustPrivilege.argtypes = [ULONG, BOOL, BOOL, POINTER(BOOL)]
	_RtlAdjustPrivilege.restype  = NTSTATUS

	
	CurrentThread = thread_or_process #False = enable for whole process, True = current thread only
	Enabled = BOOL()
	
	status = _RtlAdjustPrivilege(privilige_id, enable, CurrentThread, ctypes.byref(Enabled))
	if status != 0:
		raise Exception('Failed call to RtlAdjustPrivilege! Status: %s' % status)
	
	return Enabled.value