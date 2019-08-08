import ctypes
import winreg
from pypykatz.commons.readers.local.common.defines import *

# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeya
def RegOpenKey(key_handle, key_path):
	_RegOpenKey = windll.Advapi32.RegOpenKeyA
	_RegOpenKey.argtypes = [HANDLE, LPSTR, PHANDLE]
	_RegOpenKey.restype = bool
	_RegOpenKey.errcheck = RaiseIfNotZero
	
	lpClass = ctypes.create_string_buffer(key_path.encode())
	key_handle_new = HANDLE()
	
	res = _RegOpenKey(key_handle, lpClass, byref(key_handle_new))
	
	return key_handle_new

# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya
def RegQueryInfoKey(key_handle):
	_RegQueryInfoKey = windll.Advapi32.RegQueryInfoKeyA
	_RegQueryInfoKey.argtypes = [HKEY, LPSTR, LPDWORD, LPDWORD,LPDWORD,LPDWORD,LPDWORD,LPDWORD,LPDWORD,LPDWORD,LPDWORD,PVOID]
	_RegQueryInfoKey.restype = bool
	_RegQueryInfoKey.errcheck = RaiseIfNotZero
	
	lpClass = ctypes.create_string_buffer(b"", 255)
	lpcchClass = DWORD(255)
	lpReserved = DWORD(0)
	lpcSubKeys = DWORD(0)
	lpcbMaxSubKeyLen = DWORD(0)
	lpcbMaxClassLen = DWORD(0)
	lpcValues = DWORD(0)
	lpcbMaxValueNameLen = DWORD(0)
	lpcbMaxValueLen = DWORD(0)
	lpcbSecurityDescriptor = DWORD(0)
	lpftLastWriteTime = None
	
	res = _RegQueryInfoKey(key_handle, lpClass, lpcchClass, None, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)
	
	return (lpClass.value, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, 
			lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, 
			lpcbSecurityDescriptor, lpftLastWriteTime)

if __name__ == '__main__':
	pkey = winreg.HKEY_LOCAL_MACHINE
	for name in 'SYSTEM\\ControlSet001\\Control\\Lsa\\JD'.split('\\'):
		pkey = RegOpenKey(pkey, name)
	
	ki = RegQueryInfoKey(pkey)
	print(ki[0])
