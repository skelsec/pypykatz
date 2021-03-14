#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
import enum

class POINTER:
	def __init__(self):
		self.location = None
		self.value = None
		self.finaltype = None

	@staticmethod
	async def loadvalue(reader, finaltype = None):
		p = await POINTER.load(reader, finaltype)
		return p.value
	
	@staticmethod
	async def load(reader, finaltype):
		p = POINTER()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = finaltype
		return p

	async def read(self, reader, override_finaltype = None):
		if self.value == 0:
			return None
		pos = reader.tell()
		await reader.move(self.value)
		if override_finaltype:
			data = await override_finaltype.load(reader)
		else:
			data = await self.finaltype.load(reader)
		await reader.move(pos)
		return data
	
	async def read_raw(self, reader, size ):
		#we do not know the finaltype, just want the data
		if self.value == 0:
			return None
		pos = reader.tell()
		await reader.move(self.value)
		data = await reader.read(size)
		await reader.move(pos)
		return data
		
class PVOID(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def loadvalue(reader):
		t = await PVOID.load(reader)
		return t.value

	@staticmethod
	async def load(reader, finaltype = None):
		p = PVOID()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = None
		return p
		
class BOOL:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await BOOL.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = BOOL()
		t = await reader.read_uint()
		res.value = bool(t)
		return res
		
class BOOLEAN:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await BOOLEAN.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = BOOLEAN()
		t = await reader.read(1)
		res.value = bool(t)
		return res
		
class BYTE:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await BYTE.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = BYTE()
		t = await reader.read(1)
		res.value = t
		return res
		
class PBYTE(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = PBYTE()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = BYTE
		return p
	

class CCHAR:
	def __init__(self):
		self.value = None

	@staticmethod
	async def loadvalue(reader):
		t = await CCHAR.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = CCHAR()
		t = await reader.read(1)
		res.value = t.decode('ascii')
		return res
		
class CHAR:
	def __init__(self):
		self.value = None

	@staticmethod
	async def loadvalue(reader):
		t = await CHAR.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = CHAR()
		t = await reader.read(1)
		res.value = t.decode('ascii')
		return res
		
class UCHAR:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await UCHAR.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = UCHAR()
		t = await reader.read(1)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res

class WORD:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await WORD.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = WORD()
		t = await reader.read(2)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res

class DWORD:	
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await DWORD.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = DWORD()
		t = await reader.read(4)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res
		
class DWORDLONG:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await DWORDLONG.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = DWORDLONG()
		t = await reader.read(8)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res
		
class DWORD_PTR(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	@staticmethod
	async def load(reader):
		p = DWORD_PTR()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = DWORD
		return p
		
class DWORD32:
	def __init__(self):
		self.value = None

	@staticmethod
	async def loadvalue(reader):
		t = await DWORD32.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = DWORD32()
		t = await reader.read(4)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res

class DWORD64:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await DWORD64.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = DWORD64()
		t = await reader.read(8)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res

	
class HANDLE:	
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await HANDLE.load(reader)
		return t.value


	@staticmethod
	async def load(reader):
		res = HANDLE()
		res.value = await reader.read_uint()
		return res
		
class HFILE:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await HFILE.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = HFILE()
		res.value = await reader.read_uint()
		return res
		
class HINSTANCE:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await HINSTANCE.load(reader)
		return t.value


	@staticmethod
	async def load(reader):
		res = HINSTANCE()
		res.value = await reader.read_uint()
		return res
		

class HKEY:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await HKEY.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = HKEY()
		res.value = await reader.read_uint()
		return res


class HKL:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await HKL.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = HKL()
		res.value = await reader.read_uint()
		return res
		
class HLOCAL:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await HLOCAL.load(reader)
		return t.value


	@staticmethod
	async def load(reader):
		res = HLOCAL()
		res.value = await reader.read_uint()
		return res

class INT:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await INT.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = INT()
		res.value = await reader.read_int()
		return res
	

class INT_PTR(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = INT_PTR()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = INT
		return p

class UINT8:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await UINT8.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = UINT8()
		t = await reader.read(1)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res

class INT8:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await INT8.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = INT8()
		t = await reader.read(1)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class INT16:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await INT16.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = INT16()
		t = await reader.read(2)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class INT32:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await INT32.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = INT32()
		t = await reader.read(4)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class INT64:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await INT64.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = INT64()
		t = await reader.read(8)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class LONG:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await LONG.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = LONG()
		t = await reader.read(4)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class LONGLONG:	
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await LONGLONG.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = LONGLONG()
		t = await reader.read(8)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class LONG_PTR(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = LONG_PTR()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = LONG
		return p

class LONG32:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await LONG32.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = LONG32()
		t = await reader.read(4)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class LONG64():
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await LONG64.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = LONG64()
		t = await reader.read(8)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res

class LPARAM(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = LPARAM()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = LONG
		return p

class LPBOOL(POINTER):	
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = LPBOOL()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = BOOL
		return p

class LPBYTE(POINTER):	
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = LPBYTE()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = BYTE
		return p

class ULONG:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await ULONG.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = ULONG()
		t = await reader.read(4)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res
		
class ULONGLONG:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await ULONGLONG.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = ULONGLONG()
		t = await reader.read(8)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res

class ULONG32:	
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await ULONG32.load(reader)
		return t.value

	
	@staticmethod
	async def load(reader):
		res = ULONG32()
		t = await reader.read(4)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res
		
class ULONG64:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await ULONG64.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = ULONG64()
		t = await reader.read(8)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res
		
class PWSTR(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = PWSTR()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = None
		return p
		
class PCHAR(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = PCHAR()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = CHAR
		return p
		
class USHORT:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await USHORT.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = USHORT()
		t = await reader.read(2)
		res.value = int.from_bytes(t, byteorder = 'little', signed = False)
		return res
		
class SHORT:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await SHORT.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = SHORT()
		t = await reader.read(2)
		res.value = int.from_bytes(t, byteorder = 'little', signed = True)
		return res
		
#https://msdn.microsoft.com/en-us/library/windows/hardware/ff554296(v=vs.85).aspx
class LIST_ENTRY:
	def __init__(self):
		self.Flink = None
		self.Blink = None

	@staticmethod
	async def load(reader, finaltype = None):
		res = LIST_ENTRY()
		res.Flink = await POINTER.load(reader, finaltype)
		res.Blink = await POINTER.load(reader, finaltype)
		return res
		
class FILETIME:
	def __init__(self):
		self.dwLowDateTime = None
		self.dwHighDateTime = None
		self.value = None

	@staticmethod
	async def loadvalue(reader):
		t = await FILETIME.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader, finaltype = None):
		res = FILETIME()
		res.dwLowDateTime = await DWORD.load(reader)
		res.dwHighDateTime = await DWORD.load(reader)
		res.value = (res.dwHighDateTime.value << 32) + res.dwLowDateTime.value
		return res
		
class PUCHAR(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = PUCHAR()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = UCHAR
		return p
		
class PCWSTR(POINTER):
	def __init__(self):
		super().__init__() #with void we cannot determine the final type
	
	@staticmethod
	async def load(reader):
		p = PCWSTR()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = None
		return p
		
class SIZE_T:
	def __init__(self):
		self.value = None
	
	@staticmethod
	async def loadvalue(reader):
		t = await SIZE_T.load(reader)
		return t.value
	
	@staticmethod
	async def load(reader):
		res = SIZE_T()
		res.value = await reader.read_uint()
		return res

class LARGE_INTEGER:
	def __init__(self):
		self.LowPart = None
		self.HighPart = None
		self.QuadPart = None
	
	
	@staticmethod
	async def load(reader):
		res = LARGE_INTEGER()
		res.LowPart = await DWORD.loadvalue(reader)
		res.HighPart = await LONG.loadvalue(reader)
		res.QuadPart = await LONGLONG.loadvalue(reader)
		return res


class PSID(POINTER):
	def __init__(self):
		super().__init__()

	@staticmethod
	async def load(reader):
		p = PSID()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = SID
		return p

class SID:
	def __init__(self):
		self.Revision = None
		self.SubAuthorityCount = None
		self.IdentifierAuthority = None
		self.SubAuthority = []
	
	@staticmethod
	async def load(reader):
		res = SID()
		res.Revision = await UINT8.loadvalue(reader)
		res.SubAuthorityCount = await UINT8.loadvalue(reader)
		t = await reader.read(6)
		res.IdentifierAuthority = int.from_bytes(b'\x00\x00' + t, byteorder = 'big', signed = False)
		for _ in range(res.SubAuthorityCount):
			t = await ULONG.loadvalue(reader)
			res.SubAuthority.append(t)
		return res

	def __str__(self):
		t = 'S-%d-%d' % (self.Revision, self.IdentifierAuthority)
		for subauthority in self.SubAuthority:
			t+= '-%d' % (subauthority)
		return t
		
class LUID:
	def __init__(self):
		self.LowPart = None
		self.HighPart = None
		self.value = None

	@staticmethod
	async def loadvalue(reader):
		t = await LUID.load(reader)
		return t.value

	@staticmethod
	async def load(reader):
		res = LUID()
		res.LowPart = await DWORD.loadvalue(reader)
		res.HighPart = await LONG.loadvalue(reader)
		res.value = (res.HighPart << 32) + res.LowPart
		return res

		
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms721841(v=vs.85).aspx
class LSA_UNICODE_STRING:
	def __init__(self):
		self.Length = None
		self.MaximumLength = None
		self.Buffer = None

	@staticmethod
	async def load(reader):
		res = LSA_UNICODE_STRING()
		res.Length= await USHORT.loadvalue(reader)
		res.MaximumLength = await USHORT.loadvalue(reader)
		await reader.align()
		res.Buffer = await PWSTR.loadvalue(reader)
		return res
		
	async def read_string(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return ''
		await reader.move(self.Buffer)
		data = await reader.read(self.Length)
		data_str = data.decode('utf-16-le').rstrip('\0')
		return data_str
		
	async def read_data(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		await reader.move(self.Buffer)
		return await reader.read(self.Length)
		
	async def read_maxdata(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		await reader.move(self.Buffer)
		return await reader.read(self.MaximumLength)
		
# https://msdn.microsoft.com/en-us/library/windows/hardware/ff540605(v=vs.85).aspx
class PANSI_STRING(POINTER):
	def __init__(self):
		super().__init__()

	@staticmethod
	async def load(reader):
		p = PANSI_STRING()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = ANSI_STRING
		return p
		
class ANSI_STRING:
	def __init__(self):
		self.Length = None
		self.MaximumLength = None
		self.Buffer = None

	@staticmethod
	async def load(reader):
		res = ANSI_STRING()
		res.Length = await USHORT.loadvalue(reader)
		res.MaximumLength = await USHORT.loadvalue(reader)
		res.Buffer = await PCHAR.load(reader)
		return res
		
	async def read_string(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return ''
		await reader.move(self.Buffer)
		data = await reader.read(self.Length)
		data_str = data.decode().rstrip('\0')
		return data_str
		
	async def read_data(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		await reader.move(self.Buffer)
		return await reader.read(self.Length)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378064(v=vs.85).aspx

class KerberosNameType(enum.Enum):
	KRB_NT_UNKNOWN = 0
	KRB_NT_PRINCIPAL = 1
	KRB_NT_PRINCIPAL_AND_ID = -131
	KRB_NT_SRV_INST = 2
	KRB_NT_SRV_INST_AND_ID = -132
	KRB_NT_SRV_HST = 3
	KRB_NT_SRV_XHST = 4
	KRB_NT_UID = 5
	KRB_NT_ENTERPRISE_PRINCIPAL = 10
	KRB_NT_ENT_PRINCIPAL_AND_ID = -130
	KRB_NT_MS_PRINCIPAL = -128
	KRB_NT_MS_PRINCIPAL_AND_ID = -129
	
class PKERB_EXTERNAL_NAME(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PKERB_EXTERNAL_NAME()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = KERB_EXTERNAL_NAME
		return p

class KERB_EXTERNAL_NAME:
	def __init__(self):
		self.NameType = None
		self.NameCount = None
		self.Names = []	# list of LSA_UNICODE_STRING
	
	@staticmethod
	async def load(reader):
		res = KERB_EXTERNAL_NAME()
		res.NameType = await SHORT.loadvalue(reader) #KerberosNameType(SHORT(reader).value)
		res.NameCount = await USHORT.loadvalue(reader)
		await reader.align()
		for _ in range(res.NameCount):
			t = await LSA_UNICODE_STRING.load(reader)
			res.Names.append(t)
		return res 
		
	async def read(self, reader):
		t = []
		for name in self.Names:
			x = await name.read_string(reader)
			t.append(x)
		return t
		
		
class KIWI_GENERIC_PRIMARY_CREDENTIAL:
	def __init__(self):
		self.UserName = None
		self.Domaine = None
		self.Password = None
	
	@staticmethod
	async def load(reader):
		res = KIWI_GENERIC_PRIMARY_CREDENTIAL()
		res.UserName = await LSA_UNICODE_STRING.load(reader)
		res.Domaine  = await LSA_UNICODE_STRING.load(reader)
		res.Password = await LSA_UNICODE_STRING.load(reader)
		return res 

class PRTL_BALANCED_LINKS(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PRTL_BALANCED_LINKS()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = RTL_BALANCED_LINKS
		return p

class RTL_BALANCED_LINKS:
	def __init__(self):
		self.Parent = None
		self.LeftChild = None
		self.RightChild = None
		self.Balance = None
		self.Reserved = None
	
	@staticmethod
	async def load(reader):
		res = RTL_BALANCED_LINKS()
		res.Parent = await PRTL_BALANCED_LINKS.load(reader)
		res.LeftChild = await PRTL_BALANCED_LINKS.load(reader)
		res.RightChild = await PRTL_BALANCED_LINKS.load(reader)
		res.Balance = await BYTE.loadvalue(reader)
		res.Reserved = await reader.read(3) # // align
		await reader.align()
		return res 

class PRTL_AVL_TABLE(POINTER):
	def __init__(self):
		super().__init__()
	
	@staticmethod
	async def load(reader):
		p = PRTL_AVL_TABLE()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = RTL_AVL_TABLE
		return p
		
class RTL_AVL_TABLE:
	def __init__(self):
		self.BalancedRoot = None
		self.OrderedPointer = None
		self.WhichOrderedElement = None
		self.NumberGenericTableElements = None
		self.DepthOfTree = None
		self.RestartKey = None
		self.DeleteCount = None
		self.CompareRoutine = None
		self.AllocateRoutine = None
		self.FreeRoutine = None
		self.TableContext = None
	
	@staticmethod
	async def load(reader):
		res = RTL_AVL_TABLE()
		res.BalancedRoot = await RTL_BALANCED_LINKS.load(reader)
		res.OrderedPointer = await PVOID.load(reader)
		res.WhichOrderedElement = await ULONG.loadvalue(reader)
		res.NumberGenericTableElements = await ULONG.loadvalue(reader)
		res.DepthOfTree = await ULONG.loadvalue(reader)
		await reader.align()
		res.RestartKey = await PRTL_BALANCED_LINKS.load(reader)
		res.DeleteCount = await ULONG.loadvalue(reader)
		await reader.align()
		res.CompareRoutine = await PVOID.load(reader)
		res.AllocateRoutine = await PVOID.load(reader)
		res.FreeRoutine = await PVOID.load(reader)
		res.TableContext = await PVOID.load(reader)
		return res 

class PLSAISO_DATA_BLOB(POINTER):
	def __init__(self):
		super().__init__()

	@staticmethod
	async def load(reader):
		p = PLSAISO_DATA_BLOB()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = LSAISO_DATA_BLOB
		return p
		
class LSAISO_DATA_BLOB:
	size = 9*4 + 3*16 + 16 #+sizeof array ?ANYSIZE_ARRAY
	def __init__(self):
		self.structSize = None
		self.unk0 = None
		self.typeSize = None
		self.unk1 = None
		self.unk2 = None
		self.unk3 = None
		self.unk4 = None
		self.unkKeyData = None
		self.unkData2 = None
		self.unk5 = None
		self.origSize = None
		self.data = None #size determined later
	
	@staticmethod
	async def load(reader):
		res = LSAISO_DATA_BLOB()
		res.structSize = await DWORD.loadvalue(reader)
		res.unk0 = await DWORD.loadvalue(reader)
		res.typeSize = await DWORD.loadvalue(reader)
		res.unk1 = await DWORD.loadvalue(reader)
		res.unk2 = await DWORD.loadvalue(reader)
		res.unk3 = await DWORD.loadvalue(reader)
		res.unk4 = await DWORD.loadvalue(reader)
		res.unkKeyData = await reader.read(3*16)
		res.unkData2 = await reader.read(16)
		res.unk5 = await DWORD.loadvalue(reader)
		res.origSize = await DWORD.loadvalue(reader)
		res.data = None #size determined later
		return res 
		
		
class ENC_LSAISO_DATA_BLOB:
	def __init__(self):
		self.unkData1 = None
		self.unkData2 = None
		self.data = None
	
	@staticmethod
	async def load(reader):
		res = ENC_LSAISO_DATA_BLOB()
		res.unkData1 = await reader.read(16)
		res.unkData2 = await reader.read(16)
		res.data = None #size determined later
		return res 
		
class GUID:
	def __init__(self):
		self.Data1 = None
		self.Data2 = None
		self.Data3 = None
		self.Data4 = None
		self.value = None

	@staticmethod
	async def loadvalue(reader):
		t = await GUID.load(reader)
		return t.value

	
	@staticmethod
	async def load(reader):
		res = GUID()
		res.Data1 = await DWORD.loadvalue(reader)
		res.Data2 = await WORD.loadvalue(reader)
		res.Data3 = await WORD.loadvalue(reader)
		res.Data4 = await reader.read(8)
		res.value = '-'.join([
			hex(res.Data1)[2:].zfill(8), 
			hex(res.Data2)[2:].zfill(4), 
			hex(res.Data3)[2:].zfill(4), 
			hex(int.from_bytes(res.Data4[:2], byteorder = 'big', signed = False))[2:].zfill(4),
			hex(int.from_bytes(res.Data4[2:], byteorder = 'big', signed = False))[2:].zfill(12)
		])
		return res 

class PLIST_ENTRY(POINTER):
	def __init__(self):
		super().__init__()

	@staticmethod
	async def load(reader):
		p = PLIST_ENTRY()
		p.location = reader.tell()
		p.value = await reader.read_uint()
		p.finaltype = LIST_ENTRY
		return p
		
