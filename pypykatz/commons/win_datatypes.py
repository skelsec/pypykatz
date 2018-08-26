#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum
import struct
from pypykatz.commons.common import *


class POINTER(object):
	def __init__(self, reader, finaltype):
		self.location = reader.tell()
		self.value = reader.read_uint()
		self.finaltype = finaltype

	def read(self, reader, override_finaltype=None):
		if self.value == 0:
			return None
		pos = reader.tell()
		reader.move(self.value)
		if override_finaltype:
			data = override_finaltype(reader)
		else:
			data = self.finaltype(reader)
		reader.move(pos)
		return data

	def read_raw(self, reader, size):
		# we do not know the finaltype, just want the data
		if self.value == 0:
			return None
		pos = reader.tell()
		reader.move(self.value)
		data = reader.read(size)
		reader.move(pos)
		return data


class PVOID(POINTER):
	def __init__(self, reader):
		super(PVOID, self).__init__(reader, None)  # with void we cannot determine the final type


class BOOL:
	def __init__(self, reader):
		self.value = bool(reader.read_uint())


class BOOLEAN:
	def __init__(self, reader):
		self.value = reader.read(1)


class BYTE:
	def __init__(self, reader):
		self.value = reader.read(1)


class PBYTE(POINTER):
	def __init__(self, reader):
		super(PBYTE, self).__init__(reader, BYTE)


class CCHAR:
	def __init__(self, reader):
		self.value = reader.read(1).decode('ascii')


class CHAR:
	def __init__(self, reader):
		self.value = reader.read(1).decode('ascii')


class UCHAR:
	def __init__(self, reader):
		self.value = ord(reader.read(1))


class WORD:
	def __init__(self, reader):
		self.value = struct.unpack("<H", reader.read(2))[0]


class DWORD:
	def __init__(self, reader):
		self.value = struct.unpack("<L", reader.read(4))[0]


class DWORDLONG:
	def __init__(self, reader):
		self.value = struct.unpack("<Q", reader.read(8))[0]


class DWORD_PTR(POINTER):
	def __init__(self, reader):
		super(DWORD_PTR, self).__init__(reader, DWORD)


class DWORD32:
	def __init__(self, reader):
		self.value = struct.unpack("<L", reader.read(4))[0]


class DWORD64:
	def __init__(self, reader):
		self.value = struct.unpack("<Q", reader.read(8))[0]


class HANDLE:
	def __init__(self, reader):
		self.value = reader.read_uint()


class HFILE:
	def __init__(self, reader):
		self.value = struct.unpack("<L", reader.read(4))[0]


class HINSTANCE:
	def __init__(self, reader):
		self.value = reader.read_uint()


class HKEY:
	def __init__(self, reader):
		self.value = reader.read_uint()


class HKL:
	def __init__(self, reader):
		self.value = reader.read_uint()


class HLOCAL:
	def __init__(self, reader):
		self.value = reader.read_uint()


class INT:
	def __init__(self, reader):
		self.value = reader.read_int()


class INT_PTR(POINTER):
	def __init__(self, reader):
		super(INT_PTR, self).__init__(reader, INT)


class UINT8:
	def __init__(self, reader):
		self.value = ord(reader.read(1))


class INT8:
	def __init__(self, reader):
		self.value = ord(reader.read(1))


class INT16:
	def __init__(self, reader):
		self.value = struct.unpack("<h", reader.read(2))[0]


class INT32:
	def __init__(self, reader):
		self.value = struct.unpack("<l", reader.read(4))[0]


class INT64:
	def __init__(self, reader):
		self.value = struct.unpack("<q", reader.read(8))[0]


class LONG:
	def __init__(self, reader):
		self.value = struct.unpack("<l", reader.read(4))[0]


class LONGLONG:
	def __init__(self, reader):
		self.value = struct.unpack("<q", reader.read(8))[0]


class LONG_PTR(POINTER):
	def __init__(self, reader):
		super(LONG_PTR, self).__init__(reader, LONG)


class LONG32:
	def __init__(self, reader):
		self.value = struct.unpack("<q", reader.read(8))[0]


class LONG64():
	def __init__(self, reader):
		self.value = struct.unpack("<q", reader.read(8))[0]


class LPARAM(POINTER):
	def __init__(self, reader):
		super(LPARAM, self).__init__(reader, LONG)


class LPBOOL(POINTER):
	def __init__(self, reader):
		super(LPBOOL, self).__init__(reader, BOOL)


class LPBYTE(POINTER):
	def __init__(self, reader):
		super(LPBYTE, self).__init__(reader, BYTE)


class ULONG:
	def __init__(self, reader):
		self.value = struct.unpack("<L", reader.read(4))[0]


class ULONGLONG:
	def __init__(self, reader):
		self.value = struct.unpack("<Q", reader.read(8))[0]


class ULONG32:
	def __init__(self, reader):
		self.value = struct.unpack("<L", reader.read(4))[0]


class ULONG64:
	def __init__(self, reader):
		self.value = struct.unpack("<Q", reader.read(8))[0]


class PWSTR(POINTER):
	def __init__(self, reader):
		super(PWSTR, self).__init__(reader, None)


class PCHAR(POINTER):
	def __init__(self, reader):
		super(PCHAR, self).__init__(reader, CHAR)


class USHORT:
	def __init__(self, reader):
		self.value = struct.unpack("<H", reader.read(2))[0]


class SHORT:
	def __init__(self, reader):
		self.value = struct.unpack("<h", reader.read(2))[0]


# https://msdn.microsoft.com/en-us/library/windows/hardware/ff554296(v=vs.85).aspx
class LIST_ENTRY:
	def __init__(self, reader, finaltype=None):
		self.Flink = POINTER(reader, finaltype)
		self.Blink = POINTER(reader, finaltype)


class FILETIME:
	def __init__(self, reader):
		self.dwLowDateTime = DWORD(reader)
		self.dwHighDateTime = DWORD(reader)
		self.value = (self.dwHighDateTime.value << 32) + self.dwLowDateTime.value


class PUCHAR(POINTER):
	def __init__(self, reader):
		super(PUCHAR, self).__init__(reader, UCHAR)


class PCWSTR(POINTER):
	def __init__(self, reader):
		super(PCWSTR, self).__init__(reader, None)


class SIZE_T:
	def __init__(self, reader):
		self.value = reader.read_uint()

class LARGE_INTEGER:
	def __init__(self, reader):
		self.LowPart = DWORD(reader).value
		self.HighPart = LONG(reader).value
		self.QuadPart = LONGLONG(reader).value

class PSID(POINTER):
	def __init__(self, reader):
		super(PSID, self).__init__(reader, SID)

class SID:
	def __init__(self, reader):
		self.Revision = UINT8(reader).value
		self.SubAuthorityCount = UINT8(reader).value
		self.IdentifierAuthority = struct.unpack(">Q", b'\x00\x00' + reader.read(6))[0]
		self.SubAuthority = []
		for i in range(self.SubAuthorityCount):
			self.SubAuthority.append(ULONG(reader).value)
	
	def __str__(self):
		t = 'S-%d-%d' % (self.Revision, self.IdentifierAuthority)
		for subauthority in self.SubAuthority:
			t+= '-%d' % (subauthority)
		return t
		
class LUID:
	def __init__(self, reader):
		self.LowPart = DWORD(reader).value
		self.HighPart = LONG(reader).value
		self.value = (self.HighPart << 32) + self.LowPart
		
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms721841(v=vs.85).aspx
class LSA_UNICODE_STRING:
	def __init__(self, reader):
		self.Length= USHORT(reader).value
		self.MaximumLength = USHORT(reader).value
		reader.align()
		self.Buffer = PWSTR(reader).value
		
	def read_string(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return ''
		reader.move(self.Buffer)
		data = reader.read(self.Length)
		data_str = data.decode('utf-16-le').rstrip('\0')
		return data_str
		
	def read_data(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		reader.move(self.Buffer)
		return reader.read(self.Length)
		
	def read_maxdata(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		reader.move(self.Buffer)
		return reader.read(self.MaximumLength)
		
# https://msdn.microsoft.com/en-us/library/windows/hardware/ff540605(v=vs.85).aspx
class PANSI_STRING(POINTER):
	def __init__(self, reader):
		super(PANSI_STRING, self).__init__(reader, ANSI_STRING)
		
class ANSI_STRING:
	def __init__(self, reader):
		self.Length = USHORT(reader)
		self.MaximumLength = USHORT(reader)
		#reader.align()
		self.Buffer = PCHAR(reader).value
		
	def read_string(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return ''
		reader.move(self.Buffer)
		data = reader.read(self.Length)
		data_str = data.decode().rstrip('\0')
		return data_str
		
	def read_data(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		reader.move(self.Buffer)
		return reader.read(self.Length)

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
	def __init__(self, reader):
		super(PKERB_EXTERNAL_NAME, self).__init__(reader, KERB_EXTERNAL_NAME)

class KERB_EXTERNAL_NAME:
	def __init__(self, reader):
		self.NameType = SHORT(reader).value #KerberosNameType(SHORT(reader).value)
		self.NameCount = USHORT(reader).value
		reader.align()
		self.Names = []	# list of LSA_UNICODE_STRING
		for i in range(self.NameCount):
			self.Names.append(LSA_UNICODE_STRING(reader))
		
	def read(self, reader):
		t = []
		for name in self.Names:
			t.append(name.read_string(reader))
		return t
		
		
class KIWI_GENERIC_PRIMARY_CREDENTIAL:
	def __init__(self, reader):
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.Password = LSA_UNICODE_STRING(reader)

class PRTL_BALANCED_LINKS(POINTER):
	def __init__(self, reader):
		super(PRTL_BALANCED_LINKS, self).__init__(reader, RTL_BALANCED_LINKS)

class RTL_BALANCED_LINKS:
	def __init__(self, reader):
		self.Parent = PRTL_BALANCED_LINKS(reader)
		self.LeftChild = PRTL_BALANCED_LINKS(reader)
		self.RightChild = PRTL_BALANCED_LINKS(reader)
		self.Balance = BYTE(reader).value
		self.Reserved = reader.read(3) # // align
		reader.align()

class PRTL_AVL_TABLE(POINTER):
	def __init__(self, reader):
		super(PRTL_AVL_TABLE, self).__init__(reader, RTL_AVL_TABLE)
		
class RTL_AVL_TABLE:
	def __init__(self, reader):
		self.BalancedRoot = RTL_BALANCED_LINKS(reader)
		self.OrderedPointer = PVOID(reader)
		self.WhichOrderedElement = ULONG(reader).value
		self.NumberGenericTableElements = ULONG(reader).value
		self.DepthOfTree = ULONG(reader).value
		reader.align()
		self.RestartKey = PRTL_BALANCED_LINKS(reader)
		self.DeleteCount = ULONG(reader).value
		reader.align()
		self.CompareRoutine = PVOID (reader)# //
		self.AllocateRoutine = PVOID(reader) #//
		self.FreeRoutine = PVOID(reader)#//
		TableContext = PVOID(reader)

class PLSAISO_DATA_BLOB(POINTER):
	def __init__(self, reader):
		super(PLSAISO_DATA_BLOB, self).__init__(reader, LSAISO_DATA_BLOB)
		
class LSAISO_DATA_BLOB:
	size = 9*4 + 3*16 + 16 #+sizeof array ?ANYSIZE_ARRAY
	def __init__(self, reader):
		self.structSize = DWORD(reader)
		self.unk0 = DWORD(reader)
		self.typeSize = DWORD(reader)
		self.unk1 = DWORD(reader)
		self.unk2 = DWORD(reader)
		self.unk3 = DWORD(reader)
		self.unk4 = DWORD(reader)
		self.unkKeyData = reader.read(3*16)
		self.unkData2 = reader.read(16)
		self.unk5 = DWORD(reader)
		self.origSize = DWORD(reader)
		self.data = None #size determined later
		
		
class ENC_LSAISO_DATA_BLOB:
	def __init__(self, reader):
		self.unkData1 = reader.read(16)
		self.unkData2 = reader.read(16)
		self.data = None #size determined later
		
class GUID:
	def __init__(self, reader):
		self.Data1 = DWORD(reader).value
		self.Data2 = WORD(reader).value
		self.Data3 = WORD(reader).value
		self.Data4 = reader.read(8)
		
		self.value = '-'.join([
			hex(self.Data1)[2:], 
			hex(self.Data2)[2:], 
			hex(self.Data3)[2:], 
			hex(struct.unpack(">L", self.Data4[:4])[0])[2:],
			hex(struct.unpack(">L", self.Data4[4:])[0])[2:]
		])
