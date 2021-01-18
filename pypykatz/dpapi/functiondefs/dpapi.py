from ctypes import byref, Structure, c_char, c_buffer, string_at, windll, c_void_p, c_uint32, POINTER, c_wchar_p, WinError

LPWSTR      = c_wchar_p
LPVOID      = c_void_p
PVOID       = LPVOID
PPVOID      = POINTER(PVOID)
DWORD       = c_uint32

def RaiseIfZero(result, func = None, arguments = ()):
    """
    Error checking for most Win32 API calls.

    The function is assumed to return an integer, which is C{0} on error.
    In that case the C{WindowsError} exception is raised.
    """
    if not result:
        raise WinError()
    return result

class DATA_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', POINTER(c_char))
	]
PDATA_BLOB = POINTER(DATA_BLOB)

# https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
def CryptUnprotectData(enc_blob, entropy = None, to_prompt = False):
	_CryptUnprotectData = windll.crypt32.CryptUnprotectData
	_CryptUnprotectData.argtypes = [PDATA_BLOB, LPWSTR, PDATA_BLOB, PVOID, DWORD, DWORD, PDATA_BLOB]
	_CryptUnprotectData.restype = bool
	_CryptUnprotectData.errcheck = RaiseIfZero
	
	buffer_in      = c_buffer(enc_blob, len(enc_blob))
	blob_in        = DATA_BLOB(len(enc_blob), buffer_in)
	blob_out       = DATA_BLOB()

	if entropy is not None:
		buffer_entropy = c_buffer(entropy, len(entropy))
		blob_entropy   = DATA_BLOB(len(entropy), buffer_entropy)
		_CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0, byref(blob_out))
	else:
		_CryptUnprotectData(byref(blob_in), None, None, None, 0, 0, byref(blob_out))

	dec_data = string_at(blob_out.pbData, blob_out.cbData)
	return dec_data

if __name__ == '__main__':
	enc_data = bytes.fromhex('01000000d08c9ddf0115d1118c7a00c04fc297eb010000005f3d1f4bf6f35b469eb9719205c9c1160000000002000000000003660000c000000010000000ef8ad11a2c0a0fa867c4bc8ea535c3b10000000004800000a000000010000000beb718a641f76dff7fb9f6edb0da69061800000068cdb387e412d6e097cd7db04af8638247b9b4987cd5048714000000bb10d25466234b082ac4052360ed3d57e8951367')
	dec_data = CryptUnprotectData(enc_data)
	print(dec_data)