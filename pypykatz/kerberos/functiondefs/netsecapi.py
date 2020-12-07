import enum
import io
from ctypes import c_byte, c_wchar, c_char_p, addressof, c_ubyte, c_int16, c_longlong, cast, byref, Structure, c_char, c_buffer, string_at, windll, c_void_p, c_uint32, POINTER, c_wchar_p, WinError, sizeof, c_int32, c_uint16, create_string_buffer
from pypykatz.commons.common import hexdump

BYTE        = c_ubyte
UCHAR       = BYTE
SHORT       = c_int16
USHORT      = c_uint16
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
LARGE_INTEGER = c_longlong
PLARGE_INTEGER = POINTER(LARGE_INTEGER)


LSA_OPERATIONAL_MODE = ULONG
PLSA_OPERATIONAL_MODE = POINTER(LSA_OPERATIONAL_MODE)


ERROR_SUCCESS                       = 0


class SID:
	def __init__(self):
		self.Revision = None
		self.SubAuthorityCount = None
		self.IdentifierAuthority = None
		self.SubAuthority = []

	def __str__(self):
		t = 'S-1-'
		if self.IdentifierAuthority < 2**32:
			t += str(self.IdentifierAuthority)
		else:
			t += '0x' + self.IdentifierAuthority.to_bytes(6, 'big').hex().upper().rjust(12, '0')
		for i in self.SubAuthority:
			t += '-' + str(i)
		return t

	@staticmethod
	def from_ptr(ptr):
		if ptr == None:
			return None
		data = string_at(ptr, 8)
		buff = io.BytesIO(data)
		sid = SID()
		sid.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.SubAuthorityCount = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.IdentifierAuthority = int.from_bytes(buff.read(6), 'big', signed = False)

		data = string_at(ptr+8, sid.SubAuthorityCount*4)
		buff = io.BytesIO(data)
		for _ in range(sid.SubAuthorityCount):
			sid.SubAuthority.append(int.from_bytes(buff.read(4), 'little', signed = False))
		return sid

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

class LSA_STRING(Structure):
	_fields_ = [
		("Length",          USHORT),
		("MaximumLength",   USHORT),
		("Buffer",          POINTER(c_char)),
	]
	def to_string(self):
		return string_at(self.Buffer, self.MaximumLength).decode()

PLSA_STRING = POINTER(LSA_STRING)

class LSA_UNICODE_STRING(Structure):
	_fields_ = [
		("Length",          USHORT),
		("MaximumLength",   USHORT),
		("Buffer",          POINTER(c_char)),
	]

	@staticmethod
	def from_string(s):
		s = s.encode('utf-16-le')
		lus = LSA_UNICODE_STRING()
		lus.Buffer = create_string_buffer(s, len(s))
		lus.MaximumLength = len(s)+1
		lus.Length = len(s)
		return lus

	def to_string(self):
		return string_at(self.Buffer, self.MaximumLength).decode('utf-16-le').replace('\x00','')

PLSA_UNICODE_STRING = POINTER(LSA_UNICODE_STRING)

class LSA_LAST_INTER_LOGON_INFO(Structure):
	_fields_ = [
		("LastSuccessfulLogon", LARGE_INTEGER),
		("LastFailedLogon",	LARGE_INTEGER),
		("FailedAttemptCountSinceLastSuccessfulLogon", ULONG)
	]
	def to_dict(self):
		return {
			"LastSuccessfulLogon" : self.LastSuccessfulLogon,
			"LastFailedLogon" : self.LastFailedLogon,
			"FailedAttemptCountSinceLastSuccessfulLogon" : self.FailedAttemptCountSinceLastSuccessfulLogon
		}
PLSA_LAST_INTER_LOGON_INFO = POINTER(LSA_LAST_INTER_LOGON_INFO)

class SECURITY_LOGON_SESSION_DATA(Structure):
	_fields_ = [
		("Size",                  ULONG),
		("LogonId",               LUID),
		("UserName",              LSA_UNICODE_STRING),
		("LogonDomain",           LSA_UNICODE_STRING),
		("AuthenticationPackage", LSA_UNICODE_STRING),
		("LogonType",             ULONG),
		("Session",               ULONG),
		("Sid",                   PVOID),
		("LogonTime",             LARGE_INTEGER),
		("LogonServer",           LSA_UNICODE_STRING),
		("DnsDomainName",         LSA_UNICODE_STRING),
		("Upn",                   LSA_UNICODE_STRING),
		("UserFlags",             ULONG),
		("LastLogonInfo",         LSA_LAST_INTER_LOGON_INFO),
		("LogonScript",           LSA_UNICODE_STRING),
		("ProfilePath",           LSA_UNICODE_STRING),
		("HomeDirectory",         LSA_UNICODE_STRING),
		("HomeDirectoryDrive",    LSA_UNICODE_STRING),
		("LogoffTime",            LARGE_INTEGER),
		("KickOffTime",           LARGE_INTEGER),
		("PasswordLastSet",       LARGE_INTEGER),
		("PasswordCanChange",     LARGE_INTEGER),
		("PasswordMustChange",    LARGE_INTEGER),
	]

	def to_dict(self):
		return {
			"LogonId":               self.LogonId.to_int(),
			"UserName":              self.UserName.to_string(),
			"LogonDomain":           self.LogonDomain.to_string(),
			"AuthenticationPackage": self.AuthenticationPackage.to_string(),
			"LogonType":             self.LogonType,
			"Session":               self.Session,
			"Sid":                   str(SID.from_ptr(self.Sid)), #PVOID), # PSID
			"LogonTime":             self.LogonTime,
			"LogonServer":           self.LogonServer.to_string(),
			"DnsDomainName":         self.DnsDomainName.to_string(),
			"Upn":                   self.Upn.to_string(),
			"UserFlags":             self.UserFlags,
			"LastLogonInfo":         self.LastLogonInfo.to_dict(),
			"LogonScript":           self.LogonScript.to_string(),
			"ProfilePath":           self.ProfilePath.to_string(),
			"HomeDirectory":         self.HomeDirectory.to_string(),
			"HomeDirectoryDrive":    self.HomeDirectoryDrive.to_string(),
			"LogoffTime":            self.LogoffTime,
			"KickOffTime":           self.KickOffTime,
			"PasswordLastSet":       self.PasswordLastSet,
			"PasswordCanChange":     self.PasswordCanChange,
			"PasswordMustChange":    self.PasswordMustChange,
		}

PSECURITY_LOGON_SESSION_DATA = POINTER(SECURITY_LOGON_SESSION_DATA)      


class KERB_PURGE_TKT_CACHE_REQUEST(Structure):
	_fields_ = [
		("MessageType", DWORD),
		("LogonId",     LUID),
		("ServerName",  LSA_STRING),
		("RealmName",   LSA_STRING),
	]

	def __init__(self, logonid = 0, servername=None, realname = None):
		if isinstance(logonid, int):
			logonid = LUID.from_int(logonid)
		
		super(KERB_PURGE_TKT_CACHE_REQUEST, self).__init__(KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage.value, logonid)

class KERB_TICKET_CACHE_INFO(Structure):
	_fields_ = [
		("ServerName", LSA_UNICODE_STRING),
		("RealmName",  LSA_UNICODE_STRING),
		("StartTime",  LARGE_INTEGER),
		("EndTime",    LARGE_INTEGER),
		("RenewTime",  LARGE_INTEGER), 
		("EncryptionType", LONG),    
		("TicketFlags", ULONG)      
	]

	def to_dict(self):
		return {
			"ServerName" : self.ServerName.to_string(),
			"RealmName" : self.RealmName.to_string(),
			"StartTime" : self.StartTime,
			"EndTime" : self.EndTime,
			"RenewTime" : self.RenewTime,
			"EncryptionType" : self.EncryptionType,
			"TicketFlags" : self.TicketFlags,
		}
PKERB_TICKET_CACHE_INFO = POINTER(KERB_TICKET_CACHE_INFO)

class KERB_CRYPTO_KEY(Structure):
	_fields_ = [
		("KeyType", LONG),
		("Length",  ULONG),
		("Value",   PVOID), #PUCHAR
	]

	def to_dict(self):
		return {
			'KeyType' : self.KeyType,
			'Key' : string_at(self.Value, self.Length)
		}
			
PKERB_CRYPTO_KEY = POINTER(KERB_CRYPTO_KEY)
  
class KERB_EXTERNAL_NAME(Structure):
	_fields_ = [
		("NameType", SHORT), 
		("NameCount", USHORT),        
		("Names", LSA_UNICODE_STRING) #LIST!!!! not implemented!
	]		
PKERB_EXTERNAL_NAME = POINTER(KERB_EXTERNAL_NAME)

class KERB_EXTERNAL_TICKET(Structure):
	_fields_ = [
		("ServiceName" ,         PVOID), #PKERB_EXTERNAL_NAME
		("TargetName" ,          PVOID), #PKERB_EXTERNAL_NAME
		("ClientName" ,          PVOID), #PKERB_EXTERNAL_NAME
		("DomainName" ,          LSA_UNICODE_STRING),
		("TargetDomainName" ,    LSA_UNICODE_STRING),
		("AltTargetDomainName" , LSA_UNICODE_STRING),
		("SessionKey" ,          KERB_CRYPTO_KEY),
		("TicketFlags" ,         ULONG),
		("Flags" ,               ULONG),
		("KeyExpirationTime" ,   LARGE_INTEGER),
		("StartTime" ,           LARGE_INTEGER),
		("EndTime" ,             LARGE_INTEGER),
		("RenewUntil" ,          LARGE_INTEGER),
		("TimeSkew" ,            LARGE_INTEGER),
		("EncodedTicketSize" ,   ULONG),
		("EncodedTicket" ,       PVOID)
	]

	def get_data(self):
		return {
			'Key' : self.SessionKey.to_dict(),
			'Ticket' : string_at(self.EncodedTicket, self.EncodedTicketSize)
		}

PKERB_EXTERNAL_TICKET = KERB_EXTERNAL_TICKET

class KERB_QUERY_TKT_CACHE_REQUEST(Structure):
	_fields_ = [
		("MessageType", DWORD),
		("LogonId",     LUID),
	]

	def __init__(self, logonid = 0):
		if isinstance(logonid, int):
			logonid = LUID.from_int(logonid)
		
		super(KERB_QUERY_TKT_CACHE_REQUEST, self).__init__(KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage.value, logonid)

class KERB_QUERY_TKT_CACHE_RESPONSE_SIZE(Structure):
	_fields_ = [
		("MessageType", DWORD),
		("CountOfTickets", ULONG),
	]
class KERB_QUERY_TKT_CACHE_RESPONSE(Structure):
	_fields_ = [
		("MessageType", DWORD),
		("CountOfTickets", ULONG),
		("Tickets", KERB_TICKET_CACHE_INFO) #array of tickets!!
	]

class KERB_SUBMIT_TKT_REQUEST(Structure):
	_fields_ = [
		("MessageType",     DWORD),
		("LogonId",         LUID),
		("TicketFlags",     ULONG),
		("Key",             KERB_CRYPTO_KEY),
		("KerbCredSize",    ULONG),
		("KerbCredOffset" , ULONG)
	]

KERB_SUBMIT_TKT_REQUEST_OFFSET = sizeof(KERB_SUBMIT_TKT_REQUEST())

def submit_tkt_helper(ticket_data, logonid=0):
	print(ticket_data[:0x10])
	offset = KERB_SUBMIT_TKT_REQUEST_OFFSET - 4
	if isinstance(logonid, int):
		logonid = LUID.from_int(logonid)

	class KERB_SUBMIT_TKT_REQUEST(Structure):
		_pack_ = 4
		_fields_ = [
			("MessageType",     DWORD),
			("LogonId",         LUID),
			("TicketFlags",     ULONG),
			#("KeyType", LONG),
			("Length",  ULONG),
			("Value",   PVOID), #PUCHAR
			("KerbCredSize",    ULONG),
			("KerbCredOffset" , ULONG),
			("TicketData"     , c_byte * len(ticket_data))
		]

	req = KERB_SUBMIT_TKT_REQUEST()
	req.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage.value
	req.LogonId = logonid
	req.TicketFlags = 0
	req.Key = KERB_CRYPTO_KEY() #empty key
	req.KerbCredSize = len(ticket_data)
	#req.KerbCredOffset = 
	req.TicketData = (c_byte * len(ticket_data))(*ticket_data)


	struct_end = addressof(req) + sizeof(req)
	print('struct_end %s' % hex(struct_end))
	ticketdata_start = struct_end - len(ticket_data)
	targetname_start_padded = ticketdata_start - (ticketdata_start % sizeof(c_void_p))
	print('targetname_start_padded %s' % hex(targetname_start_padded))
	print('offset %s' % offset)
	print('len(ticket_data) %s' % len(ticket_data))
	req.KerbCredOffset = offset #targetname_start_padded

	print(hexdump(string_at(addressof(req), sizeof(req)), start = addressof(req)))
	print()
	print(hexdump(string_at(addressof(req) + req.KerbCredOffset, 10 )))
	if string_at(addressof(req) + req.KerbCredOffset, req.KerbCredSize) != ticket_data:
		print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')

	return req

class KERB_RETRIEVE_TKT_REQUEST(Structure):
	_fields_ = [
		("MessageType",       DWORD),
		("LogonId",           LUID),
		("TargetName",        LSA_UNICODE_STRING),        
		("TicketFlags",       ULONG),
		("CacheOptions",      ULONG),
		("EncryptionType",    LONG),
		("CredentialsHandle", PVOID), #SecHandle
	]

	def __init__(self, targetname, ticketflags = 0x0, cacheoptions = 0x8, encryptiontype = 0x0, logonid = 0):
		if isinstance(logonid, int):
			logonid = LUID.from_int(logonid)
		
		super(KERB_RETRIEVE_TKT_REQUEST, self).__init__(
			KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage.value, 
			logonid,
			LSA_UNICODE_STRING.from_string(targetname),
			ticketflags,
			cacheoptions,
			encryptiontype,
			None,
		)

def retrieve_tkt_helper(targetname, logonid = 0, ticketflags = 0x0, cacheoptions = 0x8, encryptiontype = 0x0, temp_offset = 0):
	# Rubeus helped me here with the info that the "targetname" structure's internal pointer 
	# must be pointing to the bottom of the actual KERB_RETRIEVE_TKT_REQUEST otherwise you will get a generic error
	# Sadly that wasn't completely enough because <insert vauge reasons here>. So I introduced an extra pointer to serve
	# as a platform-independent padding between the oringinal structure and the actual targetname bytes.
	#
	# For reference:
	# https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs

	if isinstance(logonid, int):
		logonid = LUID.from_int(logonid)
	
	targetname_enc = targetname.encode('utf-16-le') + b'\x00\x00'
	targetname_len_alloc = len(targetname_enc)
	class KERB_RETRIEVE_TKT_REQUEST(Structure):
		_fields_ = [
			("MessageType",       DWORD),
			("LogonId",           LUID),
			("TargetName",        LSA_UNICODE_STRING),        
			("TicketFlags",       ULONG),
			("CacheOptions",      ULONG),
			("EncryptionType",    LONG),
			("CredentialsHandle", PVOID), #SecHandle
			("UNK",               PVOID), #I put this here otherwise there is an error "Invalid parameter". Probably padding issue but  I dunno
			("TargetNameData",    (c_byte * targetname_len_alloc)), 
		]
	
	req = KERB_RETRIEVE_TKT_REQUEST()
	req.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage.value
	req.LogonId = logonid
	req.TicketFlags = ticketflags
	req.CacheOptions = cacheoptions
	req.EncryptionType = encryptiontype
	req.TargetNameData = (c_byte * len(targetname_enc))(*targetname_enc) 

	struct_end = addressof(req) + sizeof(req)
	targetname_start = struct_end - targetname_len_alloc
	targetname_start_padded = targetname_start - (targetname_start % sizeof(c_void_p))

	lsa_target = LSA_UNICODE_STRING()
	lsa_target.Length = len(targetname.encode('utf-16-le'))
	lsa_target.MaximumLength = targetname_len_alloc
	lsa_target.Buffer = cast(targetname_start_padded,  POINTER(c_char))

	req.TargetName = lsa_target

	#print(targetname_start_padded)
	#print(lsa_target.Buffer.contents)
	##print(lsa_target.to_string())
	#print(string_at(targetname_start_padded, lsa_target.MaximumLength))
	#print('a %s' % addressof(req))
	#print('s %s' % sizeof(req))
	#hd = hexdump(string_at(addressof(req), sizeof(req)), start = addressof(req))
	#print(hd)
	
	return req

class KERB_RETRIEVE_TKT_RESPONSE(Structure):
	_fields_ = [
		("Ticket",       KERB_EXTERNAL_TICKET),
	]

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

def get_lsa_error(ret_status):
	return WinError(LsaNtStatusToWinError(ret_status))

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
	
	if not isinstance(message, Structure):
		message = bytes(message)
		message_len = len(message)
	else:
		message_len = len(bytes(message))

	return_msg_p = c_void_p()
	return_msg_len = ULONG(0)
	return_status = NTSTATUS(INVALID_HANDLE_VALUE)
	_LsaCallAuthenticationPackage(lsa_handle, package_id, byref(message), message_len, byref(return_msg_p),  byref(return_msg_len), byref(return_status))

	return_msg = b''
	free_ptr = None #please free this pointer when the parsing is finished on the upper levels using LsaFreeReturnBuffer. Problem is that if we call LsaFreeReturnBuffer here then the parsing will fail if the message has nested structures with pointers involved because by the time of parsing those pointers will be freed. sad.
	if return_msg_len.value > 0:
		return_msg = string_at(return_msg_p, return_msg_len.value)
		free_ptr = return_msg_p
		#LsaFreeReturnBuffer(return_msg_p)


	return return_msg, return_status.value, free_ptr

# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumeratelogonsessions
def LsaEnumerateLogonSessions():
	#logon_process_name == This string must not exceed 127 bytes.
	_LsaEnumerateLogonSessions = windll.Secur32.LsaEnumerateLogonSessions
	_LsaEnumerateLogonSessions.argtypes = [PULONG , PVOID] #PLUID
	_LsaEnumerateLogonSessions.restype = NTSTATUS
	_LsaEnumerateLogonSessions.errcheck = LsaRaiseIfNotErrorSuccess

	LogonSessionCount = ULONG(0)
	start_luid = c_void_p()
	_LsaEnumerateLogonSessions(byref(LogonSessionCount), byref(start_luid))

	class LUIDList(Structure):
		_fields_ = [
			("LogonIds",     LUID*LogonSessionCount.value),
		]
	PLUIDList = POINTER(LUIDList)
	
	res_luids = []
	pluids = cast(start_luid, PLUIDList)
	for luid in pluids.contents.LogonIds:
		res_luids.append(luid.to_int())

	LsaFreeReturnBuffer(start_luid)

	return res_luids

# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsagetlogonsessiondata
def LsaGetLogonSessionData(luid):
	#logon_process_name == This string must not exceed 127 bytes.
	_LsaGetLogonSessionData = windll.Secur32.LsaGetLogonSessionData
	_LsaGetLogonSessionData.argtypes = [PLUID, PVOID] #PSECURITY_LOGON_SESSION_DATA
	_LsaGetLogonSessionData.restype = NTSTATUS
	_LsaGetLogonSessionData.errcheck = LsaRaiseIfNotErrorSuccess

	if isinstance(luid, int):
		luid = LUID.from_int(luid)
	
	ppsessiondata = c_void_p()
	_LsaGetLogonSessionData(byref(luid), byref(ppsessiondata))
	
	psessiondata = cast(ppsessiondata, PSECURITY_LOGON_SESSION_DATA)
	sessiondata = psessiondata.contents.to_dict()
	LsaFreeReturnBuffer(ppsessiondata)

	return sessiondata


def get_ticket_cache_info_helper(lsa_handle, package_id, luid, throw = True):
	result = []
	message = KERB_QUERY_TKT_CACHE_REQUEST(luid)
	ret_msg, ret_status, free_prt = LsaCallAuthenticationPackage(lsa_handle, package_id, message)

	if ret_status != 0:
		if throw is True:
			raise WinError(LsaNtStatusToWinError(ret_status))
		return result

	response_preparse = KERB_QUERY_TKT_CACHE_RESPONSE_SIZE.from_buffer_copy(ret_msg)
	if response_preparse.CountOfTickets > 0:
		#new class
		class KERB_QUERY_TKT_CACHE_RESPONSE_ARRAY(Structure):
			_fields_ = [
				("MessageType", DWORD),
				("CountOfTickets", ULONG),
				("Tickets", KERB_TICKET_CACHE_INFO * response_preparse.CountOfTickets)
			]
				
		response = KERB_QUERY_TKT_CACHE_RESPONSE_ARRAY.from_buffer_copy(ret_msg)
		for ticket in response.Tickets:
			result.append(ticket.to_dict())
	
		LsaFreeReturnBuffer(free_prt)
	
	return result

def extract_ticket(lsa_handle, package_id, luid, target_name):
	message = retrieve_tkt_helper(target_name, logonid=luid)
	ret_msg, ret_status, free_ptr = LsaCallAuthenticationPackage(lsa_handle, package_id, message)

	ticket = {}
	if ret_status != 0:
		raise WinError(LsaNtStatusToWinError(ret_status))
	if len(ret_msg) > 0:					
		resp = KERB_RETRIEVE_TKT_RESPONSE.from_buffer_copy(ret_msg)
		ticket = resp.Ticket.get_data()
		LsaFreeReturnBuffer(free_ptr)

	return ticket


if __name__ == '__main__':
	
	#luids = LsaEnumerateLogonSessions()
	#for luid in luids:
	#	try:
	#		session_info = LsaGetLogonSessionData(luid)
	#		print(session_info)
	#	except Exception as e:
	#		import traceback
	#		traceback.print_exc()
	#		print(e)
	from pypykatz.commons.readers.local.common.privileges import RtlAdjustPrivilege
	from pypykatz.commons.winapi.processmanipulator import ProcessManipulator
	pm = ProcessManipulator()
	


	#lsa_handle = LsaConnectUntrusted()
	
	#package_id = LsaLookupAuthenticationPackage(lsa_handle, 'kerberos')
	#print(package_id)
	#message = KERB_PURGE_TKT_CACHE_REQUEST()
	#LsaCallAuthenticationPackage(lsa_handle, package_id, message)
	#LsaDeregisterLogonProcess(lsa_handle)

	import sys

	#print(LsaGetLogonSessionData(0))
	#retrieve_tkt_helper('almaaaaasaaaa')

	#sys.exit()

	pm.getsystem()
	lsa_handle = LsaRegisterLogonProcess('HELLOOO')
	pm.dropsystem()
	package_id = LsaLookupAuthenticationPackage(lsa_handle, 'kerberos')
	
	with open('test_9.kirbi', 'rb') as f:
		ticket_data = f.read()

	luid = 0
	message = submit_tkt_helper(ticket_data, logonid=luid)
	ret_msg, ret_status, free_ptr = LsaCallAuthenticationPackage(lsa_handle, package_id, message)
	
	print(get_lsa_error(ret_status))
	print(ret_msg)

	#

	#print(lsa_handle_2)
	#LsaDeregisterLogonProcess(lsa_handle_2)
	