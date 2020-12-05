import enum
from ctypes import byref, Structure, c_char, c_buffer, string_at, windll, c_void_p, c_uint32, POINTER, c_wchar_p, WinError, sizeof, c_int32, c_uint16, create_string_buffer

LONG        = c_int32
LPWSTR      = c_wchar_p
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


LSA_OPERATIONAL_MODE = ULONG
PLSA_OPERATIONAL_MODE = POINTER(LSA_OPERATIONAL_MODE)


ERROR_SUCCESS                       = 0

class KERB_PROTOCOL_MESSAGE_TYPE(enum.Enum):
    KerbDebugRequestMessage = 0
    KerbQueryTicketCacheMessage = 1
    KerbChangeMachinePasswordMessage = 2
    KerbVerifyPacMessage = 3
    KerbRetrieveTicketMessage = 4
    KerbUpdateAddressesMessage = 5
    KerbPurgeTicketCacheMessage = 6
    KerbChangePasswordMessage = 7
    KerbRetrieveEncodedTicketMessage = 8
    KerbDecryptDataMessage = 9
    KerbAddBindingCacheEntryMessage = 10
    KerbSetPasswordMessage = 11
    KerbSetPasswordExMessage = 12
    KerbVerifyCredentialsMessage = 13
    KerbQueryTicketCacheExMessage = 14
    KerbPurgeTicketCacheExMessage = 15
    KerbRefreshSmartcardCredentialsMessage = 16
    KerbAddExtraCredentialsMessage = 17
    KerbQuerySupplementalCredentialsMessage = 18
    KerbTransferCredentialsMessage = 19
    KerbQueryTicketCacheEx2Message = 20
    KerbSubmitTicketMessage = 21
    KerbAddExtraCredentialsExMessage = 22
    KerbQueryKdcProxyCacheMessage = 23
    KerbPurgeKdcProxyCacheMessage = 24
    KerbQueryTicketCacheEx3Message = 25
    KerbCleanupMachinePkinitCredsMessage = 26
    KerbAddBindingCacheEntryExMessage = 27
    KerbQueryBindingCacheMessage = 28
    KerbPurgeBindingCacheMessage = 29
    KerbQueryDomainExtendedPoliciesMessage = 30
    KerbQueryS4U2ProxyCacheMessage = 31
    
class LUID(Structure):
	_fields_ = [
		("LowPart",	 DWORD),
		("HighPart",	LONG),
	]

PLUID = POINTER(LUID)

def luid_to_int(luid):
	return (luid.HighPart << 32) + luid.LowPart

def int_to_luid(i):
	luid = LUID()
	luid.HighPart = i >> 32
	luid.LowPart = i & 0xFFFFFFFF
	return luid

class LSA_STRING(Structure):
	_fields_ = [
		("Length",          USHORT),
		("MaximumLength",   USHORT),
		("Buffer",          POINTER(c_char)),
	]
PLSA_STRING = POINTER(LSA_STRING)

class KERB_PURGE_TKT_CACHE_REQUEST(Structure):
	_fields_ = [
		("MessageType", DWORD),
		("LogonId",     LUID),
		("ServerName",  LSA_STRING),
		("RealmName",   LSA_STRING),
	]

	def __init__(self, logonid = 0, servername=None, realname = None):
		if isinstance(logonid, int):
			logonid = int_to_luid(logonid)
		
		super(KERB_PURGE_TKT_CACHE_REQUEST, self).__init__(KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage.value, logonid)

class KERB_TICKET_CACHE_INFO_EX2(Structure):
	_fields_ = [
		("MessageType", DWORD),
		("LogonId",     LUID),
	]

	def __init__(self, logonid = 0):
		if isinstance(logonid, int):
			logonid = int_to_luid(logonid)
		
		super(KERB_TICKET_CACHE_INFO_EX2, self).__init__(KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage.value, logonid)

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

def RaiseIfZero(result, func = None, arguments = ()):
	"""
	Error checking for most Win32 API calls.

	The function is assumed to return an integer, which is C{0} on error.
	In that case the C{WindowsError} exception is raised.
	"""
	if not result:
		raise WinError()
	return result

def LsaRaiseIfNotErrorSuccess(result, func = None, arguments = ()):
	"""
	Error checking for Win32 Registry API calls.

	The function is assumed to return a Win32 error code. If the code is not
	C{ERROR_SUCCESS} then a C{WindowsError} exception is raised.
	"""
	if result != ERROR_SUCCESS:
		raise WinError(LsaNtStatusToWinError(result))
	return result

# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsantstatustowinerror
def LsaNtStatusToWinError(errcode):
	_LsaConnectUntrusted = windll.Advapi32.LsaNtStatusToWinError
	_LsaConnectUntrusted.argtypes = [NTSTATUS]
	_LsaConnectUntrusted.restype = ULONG
	
	res = _LsaConnectUntrusted(errcode)
	if res == 0x13D:
		raise Exception('ERROR_MR_MID_NOT_FOUND for %s' % errcode)
	return res


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsafreereturnbuffer
def LsaFreeReturnBuffer(pbuffer):
	_LsaFreeReturnBuffer = windll.Secur32.LsaFreeReturnBuffer
	_LsaFreeReturnBuffer.argtypes = [PVOID]
	_LsaFreeReturnBuffer.restype = NTSTATUS
	_LsaFreeReturnBuffer.errcheck = LsaRaiseIfNotErrorSuccess
	
	_LsaFreeReturnBuffer(pbuffer)

# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaconnectuntrusted
def LsaConnectUntrusted():
	_LsaConnectUntrusted = windll.Secur32.LsaConnectUntrusted
	_LsaConnectUntrusted.argtypes = [PHANDLE]
	_LsaConnectUntrusted.restype = NTSTATUS
	_LsaConnectUntrusted.errcheck = LsaRaiseIfNotErrorSuccess
	
	lsa_handle = HANDLE(INVALID_HANDLE_VALUE)
	_LsaConnectUntrusted(byref(lsa_handle))
	return lsa_handle

# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaderegisterlogonprocess
def LsaDeregisterLogonProcess(lsa_handle):
	_LsaDeregisterLogonProcess = windll.Secur32.LsaDeregisterLogonProcess
	_LsaDeregisterLogonProcess.argtypes = [HANDLE]
	_LsaDeregisterLogonProcess.restype = NTSTATUS
	_LsaDeregisterLogonProcess.errcheck = LsaRaiseIfNotErrorSuccess
	
	_LsaDeregisterLogonProcess(lsa_handle)

	return

# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaregisterlogonprocess
def LsaRegisterLogonProcess(logon_process_name):
	#logon_process_name == This string must not exceed 127 bytes.
	_LsaRegisterLogonProcess = windll.Secur32.LsaRegisterLogonProcess
	_LsaRegisterLogonProcess.argtypes = [PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE]
	_LsaRegisterLogonProcess.restype = NTSTATUS
	_LsaRegisterLogonProcess.errcheck = LsaRaiseIfNotErrorSuccess
	
	if isinstance(logon_process_name, str):
		logon_process_name = logon_process_name.encode()
		
	pname = LSA_STRING()
	pname.Buffer = create_string_buffer(logon_process_name)
	pname.Length = len(logon_process_name)
	pname.MaximumLength = len(logon_process_name)  + 1

	lsa_handle = HANDLE(INVALID_HANDLE_VALUE)
	dummy = LSA_OPERATIONAL_MODE(0)
	_LsaRegisterLogonProcess(byref(pname), byref(lsa_handle), byref(dummy))

	return lsa_handle


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage
def LsaLookupAuthenticationPackage(lsa_handle, package_name):
	#logon_process_name == This string must not exceed 127 bytes.
	_LsaLookupAuthenticationPackage = windll.Secur32.LsaLookupAuthenticationPackage
	_LsaLookupAuthenticationPackage.argtypes = [HANDLE, PLSA_STRING, PULONG]
	_LsaLookupAuthenticationPackage.restype = NTSTATUS
	_LsaLookupAuthenticationPackage.errcheck = LsaRaiseIfNotErrorSuccess
	
	if isinstance(package_name, str):
		package_name = package_name.encode()
		
	pname = LSA_STRING()
	pname.Buffer = create_string_buffer(package_name)
	pname.Length = len(package_name)
	pname.MaximumLength = len(package_name) + 1

	package_id = ULONG(0)
	_LsaLookupAuthenticationPackage(lsa_handle, byref(pname), byref(package_id))

	return package_id.value

# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage
def LsaCallAuthenticationPackage(lsa_handle, package_id, message):
	#message bytes
	_LsaCallAuthenticationPackage = windll.Secur32.LsaCallAuthenticationPackage
	_LsaCallAuthenticationPackage.argtypes = [HANDLE, ULONG, PVOID, ULONG, PVOID, PULONG, PNTSTATUS]
	_LsaCallAuthenticationPackage.restype = DWORD
	_LsaCallAuthenticationPackage.errcheck = LsaRaiseIfNotErrorSuccess
	
	message = bytes(message)
	return_msg_p = c_void_p()
	return_msg_len = ULONG(0)
	return_status = NTSTATUS(INVALID_HANDLE_VALUE)
	_LsaCallAuthenticationPackage(lsa_handle, package_id, message, len(message), return_msg_p,  byref(return_msg_len), byref(return_status))

	#print(return_msg_p)
	return_msg = string_at(return_msg_p, return_msg_len.value)
	# TODOTODODOTOAORGAFAF
	#LsaFreeReturnBuffer(return_msg_p)
	#print(return_msg)
	#print(return_status)

	return return_msg, return_status

if __name__ == '__main__':
	from pypykatz.commons.readers.local.common.privileges import RtlAdjustPrivilege
	from pypykatz.commons.winapi.processmanipulator import ProcessManipulator
	pm = ProcessManipulator()
	
	lsa_handle = LsaConnectUntrusted()
	
	#package_id = LsaLookupAuthenticationPackage(lsa_handle, 'kerberos')
	#print(package_id)
	#message = KERB_PURGE_TKT_CACHE_REQUEST()
	#LsaCallAuthenticationPackage(lsa_handle, package_id, message)
	#LsaDeregisterLogonProcess(lsa_handle)

	pm.getsystem()
	lsa_handle_2 = LsaRegisterLogonProcess('HELLOOO')
	pm.dropsystem()

	print(lsa_handle_2)
	LsaDeregisterLogonProcess(lsa_handle_2)
	