import enum
import datetime
import ctypes
from ctypes import wintypes

from pypykatz.commons.winapi.local.function_defs.defines import *
from pypykatz.commons.winapi.local.function_defs.netapi32_high import *

"""
D: NetShareEnum 
NetWkstaUserEnum
D: NetSessionEnum
D: NetLocalGroupGetMembers
DsGetSiteName
DsEnumerateDomainTrusts
D: NetApiBufferFree
"""

LMSTR = LPWSTR
MAX_PREFERRED_LENGTH = -1

# http://qaru.site/questions/901246/howto-determine-file-owner-on-windows-using-python-without-pywin32	
class SID_NAME_USE(wintypes.DWORD):
    _sid_types = dict(enumerate('''
        User Group Domain Alias WellKnownGroup DeletedAccount
        Invalid Unknown Computer Label'''.split(), 1))

    def __init__(self, value=None):
        if value is not None:
            if value not in self.sid_types:
                raise ValueError('invalid SID type')
            wintypes.DWORD.__init__(value)

    def __str__(self):
        if self.value not in self._sid_types:
            raise ValueError('invalid SID type for value: %s' % self.value)
        return self._sid_types[self.value]

    def __repr__(self):
        return 'SID_NAME_USE(%s)' % self.value

PSID_NAME_USE = ctypes.POINTER(SID_NAME_USE)


PSID_NAME_USE = ctypes.POINTER(SID_NAME_USE)

class FILE_INFO_2(Structure): 
	_fields_ = [
		('fid',DWORD),
	]
PFILE_INFO_2 = POINTER(FILE_INFO_2)

class FILE_INFO_3(Structure): 
	_fields_ = [
		('fid',DWORD),
		('permissions',DWORD),
		('num_locks',DWORD),
		('pathname',LMSTR),
		('username',LMSTR),
	]
PFILE_INFO_3 = POINTER(FILE_INFO_3)
 
class SHARE_INFO_0(Structure): 
	_fields_ = [
		('netname',LMSTR),
	]
PSHARE_INFO_0 = POINTER(SHARE_INFO_0)

class SHARE_INFO_1(Structure): 
	_fields_ = [
		('netname',LMSTR),
		('type',DWORD ),
		('remark',LMSTR ),
	]
PSHARE_INFO_1 = POINTER(SHARE_INFO_1)

class SHARE_INFO_2(Structure): 
	_fields_ = [
		('netname',LMSTR),
		('type',DWORD ),
		('remark',LMSTR ),
		('permissions',DWORD ),
		('max_uses',DWORD ),
		('current_uses',DWORD ),
		('path',LMSTR),
		('passwd',LMSTR),
	]
PSHARE_INFO_2 = POINTER(SHARE_INFO_2)

class SHARE_INFO_501(Structure): 
	_fields_ = [
		('netname',LMSTR),
		('type',DWORD ),
		('remark',LMSTR ),
		('flags',DWORD ),
	]
PSHARE_INFO_501 = POINTER(SHARE_INFO_501)

class SHARE_INFO_502(Structure): 
	_fields_ = [
		('netname',LMSTR),
		('type',DWORD ),
		('remark',LMSTR ),
		('permissions',DWORD ),
		('max_uses',DWORD ),
		('current_uses',DWORD ),
		('path',LMSTR),
		('passwd',LMSTR),
		('reserved',DWORD),
	]
PSHARE_INFO_502 = POINTER(SHARE_INFO_502)

class SHARE_INFO_503(Structure): 
	_fields_ = [
		('netname',LMSTR),
		('type',DWORD ),
		('remark',LMSTR ),
		('permissions',DWORD ),
		('max_uses',DWORD ),
		('current_uses',DWORD ),
		('path',LMSTR),
		('passwd',LMSTR),
		('servername',LMSTR),
		('reserved',DWORD),
	]
PSHARE_INFO_503 = POINTER(SHARE_INFO_503)


class SESSION_INFO_0(Structure): 
	_fields_ = [
		('cname',LMSTR),
	]
PSESSION_INFO_0 = POINTER(SESSION_INFO_0)

class SESSION_INFO_10(Structure): 
	_fields_ = [
		('cname',LMSTR),
		('username',LMSTR),
		('time',DWORD),
		('idle_time',DWORD)
	]
PSESSION_INFO_10 = POINTER(SESSION_INFO_10)

class SESSION_INFO_1(Structure): 
	_fields_ = [
		('cname',LMSTR),
		('username',LMSTR),
		('num_opens',DWORD),
		('time',DWORD),
		('idle_time',DWORD),
		('user_flags',DWORD),
	]
PSESSION_INFO_1 = POINTER(SESSION_INFO_1)

class SESSION_INFO_2(Structure): 
	_fields_ = [
		('cname',LMSTR),
		('username',LMSTR),
		('num_opens',DWORD),
		('time',DWORD),
		('idle_time',DWORD),
		('user_flags',DWORD),
		('cltype_name',LMSTR),
	]
PSESSION_INFO_2 = POINTER(SESSION_INFO_2)

class SESSION_INFO_502(Structure): 
	_fields_ = [
		('cname',LMSTR),
		('username',LMSTR),
		('num_opens',DWORD),
		('time',DWORD),
		('idle_time',DWORD),
		('user_flags',DWORD),
		('cltype_name',LMSTR),
		('transport',LMSTR),
	]
PSESSION_INFO_502 = POINTER(SESSION_INFO_502)

class LOCALGROUP_MEMBERS_INFO_0(Structure): 
	_fields_ = [
		('sid',PSID),
	]
PLOCALGROUP_MEMBERS_INFO_0 = POINTER(LOCALGROUP_MEMBERS_INFO_0)

class LOCALGROUP_MEMBERS_INFO_1(Structure): 
	_fields_ = [
		('sid',PSID),
		('sidusage',DWORD),
		('name',LMSTR),
	]
PLOCALGROUP_MEMBERS_INFO_1 = POINTER(LOCALGROUP_MEMBERS_INFO_1)

class LOCALGROUP_MEMBERS_INFO_2(Structure): 
	_fields_ = [
		('sid',PSID),
		('sidusage',DWORD),
		('domainandname',LMSTR),
	]
PLOCALGROUP_MEMBERS_INFO_2 = POINTER(LOCALGROUP_MEMBERS_INFO_2)

class LOCALGROUP_MEMBERS_INFO_3(Structure): 
	_fields_ = [
		('domainandname',LMSTR),
	]
PLOCALGROUP_MEMBERS_INFO_3 = POINTER(LOCALGROUP_MEMBERS_INFO_3)
	
class NetSessionEnumRes(enum.Enum):
	ERROR_ACCESS_DENIED = 5
	ERROR_INVALID_LEVEL = 124
	ERROR_INVALID_PARAMETER = 87
	ERROR_NOT_ENOUGH_MEMORY = 8
	NERR_ClientNameNotFound = 2312
	NERR_InvalidComputer = (2100 + 251)
	ERROR_FILE_NOT_FOUND = 2
	NERR_FileIdNotFound = 2314
	NERR_SUCCESS= 0
	ERROR_MORE_DATA = 234


# https://docs.microsoft.com/en-us/windows/desktop/api/lmapibuf/nf-lmapibuf-netapibufferfree
def NetApiBufferFree(pbuff):
	_NetApiBufferFree = windll.Netapi32.NetApiBufferFree
	_NetApiBufferFree.argtypes = [PVOID]
	_NetApiBufferFree.restype  = DWORD
	
	_NetApiBufferFree(pbuff)
	

# https://docs.microsoft.com/en-us/windows/desktop/api/lmshare/nf-lmshare-netsessionenum
def NetSessionEnum(servername = None, clientname = None, username = None, level = 10):
	def errc(result, func, arguments):
		r = NetSessionEnumRes(result)
		if r == NetSessionEnumRes.NERR_SUCCESS or r == NetSessionEnumRes.ERROR_MORE_DATA:
			return r
		raise Exception('NetSessionEnum exception! %s' % r)
		
	_NetSessionEnum = windll.Netapi32.NetSessionEnum
	_NetSessionEnum.argtypes = [LMSTR, LMSTR, LMSTR, DWORD, PVOID, DWORD, LPDWORD ,LPDWORD , LPDWORD ]
	_NetSessionEnum.restype  = DWORD
	_NetSessionEnum.errcheck  = errc
	
	buf = PVOID()
	entriesread = DWORD()
	totalentries = DWORD()
	resume_handle = DWORD(0)
	
	
	if servername:
		servername = LPWSTR(servername)
	if clientname:
		clientname = LPWSTR(clientname)
	if username:
		username = LPWSTR(username)
	
	if level == 0:
		si_type = SESSION_INFO_0
	elif level == 1:
		si_type = SESSION_INFO_1
	elif level == 2:
		si_type = SESSION_INFO_2
	elif level == 10:
		si_type = SESSION_INFO_10
	elif level == 502:
		si_type = SESSION_INFO_502
	
	else:
		raise Exception('NetSessionEnum unsupported level %s' % level)
	
	
	first_call = True
	sessions = []
	entries_read_total = 0
	while resume_handle.value != 0 or first_call:
		res = _NetSessionEnum(servername, clientname, username, level, byref(buf), MAX_PREFERRED_LENGTH, byref(entriesread), byref(totalentries), byref(resume_handle))
		first_call = False
		entries_read_total += entriesread.value
		if entriesread.value > 0:
			map = ctypes.cast(buf, POINTER(si_type*entriesread.value))
			for i in range(entriesread.value):
				sessions.append(UserSessionInfo.from_session_info(map.contents[i], level))
			NetApiBufferFree(buf)
			
		if entries_read_total == totalentries.value:
			break
		
	return sessions
	
def NetLocalGroupGetMembers(servername = None, localgroupname = None, level = 2):
	def errc(result, func, arguments):
		r = NetSessionEnumRes(result)
		if r == NetSessionEnumRes.NERR_SUCCESS or r == NetSessionEnumRes.ERROR_MORE_DATA:
			return r
		raise Exception('NetSessionEnum exception! %s' % r)
		
	_NetLocalGroupGetMembers = windll.Netapi32.NetLocalGroupGetMembers
	_NetLocalGroupGetMembers.argtypes = [LMSTR, LMSTR, DWORD, PVOID, DWORD, LPDWORD ,LPDWORD , LPDWORD]
	_NetLocalGroupGetMembers.restype  = DWORD
	_NetLocalGroupGetMembers.errcheck  = errc
	
	buf = PVOID()
	entriesread = DWORD()
	totalentries = DWORD()
	resume_handle = DWORD(0)
	
	if servername:
		servername = LPWSTR(servername)
	if localgroupname:
		localgroupname = LPWSTR(localgroupname)
	
	if level == 0:
		si_type = LOCALGROUP_MEMBERS_INFO_0
	elif level == 1:
		si_type = LOCALGROUP_MEMBERS_INFO_1
	elif level == 2:
		si_type = LOCALGROUP_MEMBERS_INFO_2
	elif level == 3:
		si_type = LOCALGROUP_MEMBERS_INFO_3
	
	else:
		raise Exception('NetLocalGroupGetMembers unsupported level %s' % level)
		
	first_call = True
	groupinfos = []
	entries_read_total = 0
	while resume_handle.value != 0 or first_call:
		res = _NetLocalGroupGetMembers(servername, localgroupname, level, byref(buf), MAX_PREFERRED_LENGTH, byref(entriesread), byref(totalentries), byref(resume_handle))
		first_call = False
		entries_read_total += entriesread.value
		if entriesread.value > 0:
			map = ctypes.cast(buf, POINTER(si_type*entriesread.value))
			for i in range(entriesread.value):
				groupinfos.append(LocalGroupInfo.from_struct(map.contents[i], level))
			NetApiBufferFree(buf)
			
		if entries_read_total == totalentries.value:
			break
	
	return groupinfos
	
def NetShareEnum(servername = None, level = 2):
	def errc(result, func, arguments):
		r = NetSessionEnumRes(result)
		if r == NetSessionEnumRes.NERR_SUCCESS or r == NetSessionEnumRes.ERROR_MORE_DATA:
			return r
		raise Exception('NetSessionEnum exception! %s' % r)
		
	_NetShareEnum = windll.Netapi32.NetShareEnum
	_NetShareEnum.argtypes = [LMSTR, DWORD, PVOID, DWORD, LPDWORD ,LPDWORD , LPDWORD]
	_NetShareEnum.restype  = DWORD
	_NetShareEnum.errcheck  = errc
	
	buf = PVOID()
	entriesread = DWORD()
	totalentries = DWORD()
	resume_handle = DWORD(0)
	
	if servername:
		servername = LPWSTR(servername)
	
	if level == 0:
		si_type = SHARE_INFO_0
	elif level == 1:
		si_type = SHARE_INFO_1
	elif level == 2:
		si_type = SHARE_INFO_2
	elif level == 502:
		si_type = SHARE_INFO_502
	elif level == 503:
		si_type = SHARE_INFO_503
	
	else:
		raise Exception('NetShareEnum unsupported level %s' % level)
		
	first_call = True
	shareinfos = []
	entries_read_total = 0
	while resume_handle.value != 0 or first_call:
		res = _NetShareEnum(servername, level, byref(buf), MAX_PREFERRED_LENGTH, byref(entriesread), byref(totalentries), byref(resume_handle))
		first_call = False
		entries_read_total += entriesread.value
		if entriesread.value > 0:
			map = ctypes.cast(buf, POINTER(si_type*entriesread.value))
			for i in range(entriesread.value):
				shareinfos.append(ShareInfo.from_struct(map.contents[i], level))
			NetApiBufferFree(buf)
			
		if entries_read_total == totalentries.value:
			break
	
	return shareinfos
	
def NetFileEnum(servername = None, basepath = None, username = None, level = 3):
	"""
	Only members of the Administrators or Account Operators local group can successfully execute 
	"""
	def errc(result, func, arguments):
		r = NetSessionEnumRes(result)
		if r == NetSessionEnumRes.NERR_SUCCESS or r == NetSessionEnumRes.ERROR_MORE_DATA:
			return r
		raise Exception('NetFileEnum exception! %s' % r)
		
	_NetFileEnum = windll.Netapi32.NetFileEnum
	_NetFileEnum.argtypes = [LMSTR,LMSTR,LMSTR, DWORD, PVOID, DWORD, LPDWORD ,LPDWORD , LPDWORD]
	_NetFileEnum.restype  = DWORD
	_NetFileEnum.errcheck  = errc
	
	buf = PVOID()
	entriesread = DWORD()
	totalentries = DWORD()
	resume_handle = DWORD(0)
	
	if servername:
		servername = LPWSTR(servername)
	if basepath:
		basepath = LPWSTR(basepath)
	if username:
		username = LPWSTR(username)
	
	if level == 2:
		si_type = FILE_INFO_2
	elif level == 3:
		si_type = FILE_INFO_3
	
	else:
		raise Exception('NetFileEnum unsupported level %s' % level)
		
	first_call = True
	shareinfos = []
	entries_read_total = 0
	while resume_handle.value != 0 or first_call:
		res = _NetFileEnum(servername, basepath, username, level, byref(buf), MAX_PREFERRED_LENGTH, byref(entriesread), byref(totalentries), byref(resume_handle))
		first_call = False
		entries_read_total += entriesread.value
		if entriesread.value > 0:
			map = ctypes.cast(buf, POINTER(si_type*entriesread.value))
			for i in range(entriesread.value):
				shareinfos.append(ShareInfo.from_struct(map.contents[i], level))
			NetApiBufferFree(buf)
			
		if entries_read_total == totalentries.value:
			break
	
	return shareinfos