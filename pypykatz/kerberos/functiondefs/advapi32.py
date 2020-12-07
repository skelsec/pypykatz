from ctypes import WinError, c_int, cast, c_int64, sizeof, windll, byref, Structure, c_ubyte, c_int16, c_int32, c_void_p, c_uint16, c_uint32, POINTER, c_longlong

BYTE        = c_ubyte
UCHAR       = BYTE
SHORT       = c_int16
USHORT      = c_uint16
LONG        = c_int32
LPVOID      = c_void_p
PVOID       = LPVOID
PPVOID      = POINTER(PVOID)
DWORD       = c_uint32
HANDLE      = LPVOID
PHANDLE     = POINTER(HANDLE)
LPHANDLE    = PHANDLE
NTSTATUS    = LONG
PNTSTATUS   = POINTER(NTSTATUS)
USHORT      = c_uint16
ULONG       = c_uint32
PULONG      = POINTER(ULONG)
LONGLONG    = c_int64

LPDWORD     = POINTER(DWORD)
LPULONG     = POINTER(ULONG)
LPLONG      = POINTER(LONG)
PDWORD      = LPDWORD

LARGE_INTEGER = c_longlong
PLARGE_INTEGER = POINTER(LARGE_INTEGER)

TOKEN_INFORMATION_CLASS = c_int

ERROR_INSUFFICIENT_BUFFER           = 122

# Standard access rights
DELETE                           = 0x00010000
READ_CONTROL                     = 0x00020000
WRITE_DAC                        = 0x00040000
WRITE_OWNER                      = 0x00080000
SYNCHRONIZE                      = 0x00100000
STANDARD_RIGHTS_REQUIRED         = 0x000F0000
STANDARD_RIGHTS_READ             = READ_CONTROL
STANDARD_RIGHTS_WRITE            = READ_CONTROL
STANDARD_RIGHTS_EXECUTE          = READ_CONTROL
STANDARD_RIGHTS_ALL              = 0x001F0000
SPECIFIC_RIGHTS_ALL              = 0x0000FFFF

# Token access rights
TOKEN_ASSIGN_PRIMARY	= 0x0001
TOKEN_DUPLICATE		 = 0x0002
TOKEN_IMPERSONATE	   = 0x0004
TOKEN_QUERY			 = 0x0008
TOKEN_QUERY_SOURCE	  = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS	 = 0x0040
TOKEN_ADJUST_DEFAULT	= 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)

# Invalid handle value is -1 casted to void pointer.
try:
	INVALID_HANDLE_VALUE = c_void_p(-1).value #-1 #0xFFFFFFFF
except TypeError:
	if sizeof(c_void_p) == 4:
		INVALID_HANDLE_VALUE = 0xFFFFFFFF
	elif sizeof(c_void_p) == 8:
		INVALID_HANDLE_VALUE = 0xFFFFFFFFFFFFFFFF
	else:
		raise

SecurityAnonymous	   = 0
SecurityIdentification  = 1
SecurityImpersonation   = 2
SecurityDelegation	  = 3

SECURITY_IMPERSONATION_LEVEL = c_int
PSECURITY_IMPERSONATION_LEVEL = POINTER(SECURITY_IMPERSONATION_LEVEL)

TOKEN_TYPE = c_int
PTOKEN_TYPE = POINTER(TOKEN_TYPE)

class LUID(Structure):
	_fields_ = [
		("LowPart",  DWORD),
		("HighPart", LONG),
	]

	def to_int(self):
		return LUID.luid_to_int(self)

	@staticmethod
	def luid_to_int(luid):
		return (luid.HighPart << 32) + luid.LowPart

	@staticmethod
	def from_int(i):
		luid = LUID()
		luid.HighPart = i >> 32
		luid.LowPart = i & 0xFFFFFFFF
		return luid

PLUID = POINTER(LUID)

class TOKEN_STATISTICS(Structure):
	_fields_ = [
		("TokenId",			   LUID),
		("AuthenticationId",   LUID),
		("ExpirationTime",	   LONGLONG),  # LARGE_INTEGER
		("TokenType",		   TOKEN_TYPE),
		("ImpersonationLevel", SECURITY_IMPERSONATION_LEVEL),
		("DynamicCharged",	   DWORD),
		("DynamicAvailable",   DWORD),
		("GroupCount",		   DWORD),
		("PrivilegeCount",	   DWORD),
		("ModifiedId",		   LUID),
	]
	
	def to_dict(self):
		return {
			"TokenId": self.TokenId.to_int(),
			"AuthenticationId": self.AuthenticationId.to_int(),
			"ExpirationTime": self.ExpirationTime,
			"TokenType": self.TokenType,
			"ImpersonationLevel": self.ImpersonationLevel,
			"DynamicCharged": self.DynamicCharged,
			"DynamicAvailable": self.DynamicAvailable,
			"GroupCount": self.GroupCount,
			"PrivilegeCount": self.PrivilegeCount,
			"ModifiedId": self.ModifiedId.to_int(),
		}
PTOKEN_STATISTICS = POINTER(TOKEN_STATISTICS)

def RaiseIfZero(result, func = None, arguments = ()):
	"""
	Error checking for most Win32 API calls.

	The function is assumed to return an integer, which is C{0} on error.
	In that case the C{WindowsError} exception is raised.
	"""
	if not result:
		raise WinError()
	return result

# BOOL WINAPI OpenProcessToken(
#   __in   HANDLE ProcessHANDLE,
#   __in   DWORD DesiredAccess,
#   __out  PHANDLE TokenHandle
# );
def OpenProcessToken(ProcessHANDLE, DesiredAccess = TOKEN_ALL_ACCESS):
	_OpenProcessToken = windll.advapi32.OpenProcessToken
	_OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
	_OpenProcessToken.restype  = bool
	_OpenProcessToken.errcheck = RaiseIfZero

	NewTokenHandle = HANDLE(INVALID_HANDLE_VALUE)
	_OpenProcessToken(ProcessHANDLE, DesiredAccess, byref(NewTokenHandle))
	return NewTokenHandle


def GetTokenInformation_tokenstatistics(hTokenHandle):
	"""
	The original function wasn't working. this one returns the SID for the token
	"""
	TokenStatistics						 = 10

	_GetTokenInformation = windll.advapi32.GetTokenInformation
	_GetTokenInformation.argtypes = [HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD]
	_GetTokenInformation.restype  = bool
	_GetTokenInformation.errcheck = RaiseIfZero
	
	ReturnLength = DWORD(0)
	try:
		#getting the correct memory allocation size
		_GetTokenInformation(hTokenHandle, TokenStatistics, None, ReturnLength, byref(ReturnLength))
	except Exception as e:
		pass
		
	TokenInformationLength = ReturnLength.value
	ReturnLength = DWORD(0)
	ti = (BYTE * TokenInformationLength)()
	_GetTokenInformation(hTokenHandle, TokenStatistics, byref(ti), TokenInformationLength, byref(ReturnLength))
	if ReturnLength.value != TokenInformationLength:
		raise WinError(ERROR_INSUFFICIENT_BUFFER)
	
	t = cast(ti, POINTER(TOKEN_STATISTICS)).contents
	res = t.to_dict()

	return res