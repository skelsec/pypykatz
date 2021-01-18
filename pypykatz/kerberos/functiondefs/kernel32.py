from ctypes import WinError, windll, c_uint32, c_void_p, c_int32

LPVOID      = c_void_p
DWORD       = c_uint32
HANDLE      = LPVOID
BOOL        = c_int32
NULL        = None

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MAXIMUM_ALLOWED = 33554432


def RaiseIfZero(result, func = None, arguments = ()):
	"""
	Error checking for most Win32 API calls.

	The function is assumed to return an integer, which is C{0} on error.
	In that case the C{WindowsError} exception is raised.
	"""
	if not result:
		raise WinError()
	return result

def CloseHandle(hHandle):
	_CloseHandle = windll.kernel32.CloseHandle
	_CloseHandle.argtypes = [HANDLE]
	_CloseHandle.restype  = bool
	_CloseHandle.errcheck = RaiseIfZero
	_CloseHandle(hHandle)

# DWORD WINAPI GetCurrentProcessId(void);
def GetCurrentProcessId():
	_GetCurrentProcessId = windll.kernel32.GetCurrentProcessId
	_GetCurrentProcessId.argtypes = []
	_GetCurrentProcessId.restype  = DWORD
	return _GetCurrentProcessId()

# HANDLE WINAPI OpenProcess(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwProcessId
# );
def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
	_OpenProcess = windll.kernel32.OpenProcess
	_OpenProcess.argtypes = [DWORD, BOOL, DWORD]
	_OpenProcess.restype  = HANDLE

	hProcess = _OpenProcess(dwDesiredAccess, bool(bInheritHandle), dwProcessId)
	if hProcess == NULL:
		raise WinError()
	return hProcess