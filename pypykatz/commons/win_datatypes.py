#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum
from minidump.win_datatypes import DWORD, LONG, LONGLONG, \
	POINTER, UINT8, ULONG, PWSTR, USHORT, PCHAR, SHORT, \
	BYTE, PVOID, WORD, DWORD64, DWORDLONG
#from pypykatz.commons.common import *

class LARGE_INTEGER:
	def __init__(self, reader):
		self.LowPart = DWORD(reader).value
		self.HighPart = LONG(reader).value
		self.QuadPart = LONGLONG(reader).value

class PSID(POINTER):
	def __init__(self, reader):
		super().__init__(reader, SID)

class SID:
	def __init__(self, reader):
		self.Revision = UINT8(reader).value
		self.SubAuthorityCount = UINT8(reader).value
		self.IdentifierAuthority = int.from_bytes(b'\x00\x00' + reader.read(6), byteorder = 'big', signed = False)
		self.SubAuthority = []
		for _ in range(self.SubAuthorityCount):
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
		super().__init__(reader, ANSI_STRING)
		
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
		super().__init__(reader, KERB_EXTERNAL_NAME)

class KERB_EXTERNAL_NAME:
	def __init__(self, reader):
		self.NameType = SHORT(reader).value #KerberosNameType(SHORT(reader).value)
		self.NameCount = USHORT(reader).value
		reader.align()
		self.Names = []	# list of LSA_UNICODE_STRING
		for _ in range(self.NameCount):
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
		super().__init__(reader, RTL_BALANCED_LINKS)

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
		super().__init__(reader, RTL_AVL_TABLE)
		
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
		super().__init__(reader, LSAISO_DATA_BLOB)
		
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
			hex(self.Data1)[2:].zfill(8), 
			hex(self.Data2)[2:].zfill(4), 
			hex(self.Data3)[2:].zfill(4), 
			hex(int.from_bytes(self.Data4[:2], byteorder = 'big', signed = False))[2:].zfill(4),
			hex(int.from_bytes(self.Data4[2:], byteorder = 'big', signed = False))[2:].zfill(12)
		])
	
	@staticmethod
	def from_string(str):
		guid = GUID()
		guid.Data1 = bytes.fromhex(str.split('-')[0])
		guid.Data2 = bytes.fromhex(str.split('-')[1])
		guid.Data3 = bytes.fromhex(str.split('-')[2])
		guid.Data4 = bytes.fromhex(str.split('-')[3])
		guid.Data4 += bytes.fromhex(str.split('-')[4])
		return guid			

class PLIST_ENTRY(POINTER):
	def __init__(self, reader):
		super().__init__(reader, LIST_ENTRY)
		
class LIST_ENTRY:
	def __init__(self, reader):
		self.location = reader.tell()
		self.Flink = PLIST_ENTRY(reader)
		self.Blink = PLIST_ENTRY(reader)

class PIMAGE_DOS_HEADER(POINTER):
	def __init__(self, reader):
		super().__init__(reader, IMAGE_DOS_HEADER)

class IMAGE_DOS_HEADER:
	def __init__(self, reader):
		self.e_magic    = WORD(reader).value
		self.e_cblp     = WORD(reader).value
		self.e_cp       = WORD(reader).value
		self.e_crlc     = WORD(reader).value
		self.e_cparhdr  = WORD(reader).value
		self.e_minalloc = WORD(reader).value
		self.e_maxalloc = WORD(reader).value
		self.e_ss       = WORD(reader).value
		self.e_sp       = WORD(reader).value
		self.e_csum     = WORD(reader).value
		self.e_ip       = WORD(reader).value
		self.e_cs       = WORD(reader).value
		self.e_lfarlc   = WORD(reader).value
		self.e_ovno     = WORD(reader).value
		self.e_res      = reader.read(8)
		self.e_oemid    = WORD(reader).value
		self.e_oeminfo  = WORD(reader).value
		self.e_res2     = reader.read(20)
		self.e_lfanew   = LONG(reader).value

IMAGE_FILE_MACHINE_I386 = 0x014c

class IMAGE_FILE_HEADER:
	def __init__(self, reader):
		self.Machine              = WORD(reader).value
		self.NumberOfSections     = WORD(reader).value
		self.TimeDateStamp        = DWORD(reader).value
		self.PointerToSymbolTable = DWORD(reader).value
		self.NumberOfSymbols      = DWORD(reader).value
		self.SizeOfOptionalHeader = WORD(reader).value
		self.Characteristics      = WORD(reader).value

class IMAGE_DATA_DIRECTORY:
	def __init__(self, reader):
		self.VirtualAddress = DWORD(reader).value
		self.Size           = DWORD(reader).value

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2

class IMAGE_OPTIONAL_HEADER64:
	
	def __init__(self, reader):
		self.Magic                       = WORD(reader).value
		self.MajorLinkerVersion          = BYTE(reader).value
		self.MinorLinkerVersion          = BYTE(reader).value
		self.SizeOfCode                  = DWORD(reader).value
		self.SizeOfInitializedData       = DWORD(reader).value
		self.SizeOfUninitializedData     = DWORD(reader).value
		self.AddressOfEntryPoint         = DWORD(reader).value
		self.BaseOfCode                  = DWORD(reader).value
		self.ImageBase                   = DWORDLONG(reader).value
		self.SectionAlignment            = DWORD(reader).value
		self.FileAlignment               = DWORD(reader).value
		self.MajorOperatingSystemVersion = WORD(reader).value
		self.MinorOperatingSystemVersion = WORD(reader).value
		self.MajorImageVersion           = WORD(reader).value
		self.MinorImageVersion           = WORD(reader).value
		self.MajorSubsystemVersion       = WORD(reader).value
		self.MinorSubsystemVersion       = WORD(reader).value
		self.Win32VersionValue           = DWORD(reader).value
		self.SizeOfImage                 = DWORD(reader).value
		self.SizeOfHeaders               = DWORD(reader).value
		self.CheckSum                    = DWORD(reader).value
		self.Subsystem                   = WORD(reader).value
		self.DllCharacteristics          = WORD(reader).value
		self.SizeOfStackReserve          = DWORDLONG(reader).value
		self.SizeOfStackCommit           = DWORDLONG(reader).value
		self.SizeOfHeapReserve           = DWORDLONG(reader).value
		self.SizeOfHeapCommit            = DWORDLONG(reader).value
		self.LoaderFlags                 = DWORD(reader).value
		self.NumberOfRvaAndSizes         = DWORD(reader).value
		self.DataDirectory               = [IMAGE_DATA_DIRECTORY(reader) for _ in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]

class IMAGE_OPTIONAL_HEADER32:
	def __init__(self, reader):
		self.Magic                       = WORD(reader).value
		self.MajorLinkerVersion          = BYTE(reader).value
		self.MinorLinkerVersion          = BYTE(reader).value
		self.SizeOfCode                  = DWORD(reader).value
		self.SizeOfInitializedData       = DWORD(reader).value
		self.SizeOfUninitializedData     = DWORD(reader).value
		self.AddressOfEntryPoint         = DWORD(reader).value
		self.BaseOfCode                  = DWORD(reader).value
		self.BaseOfData                  = DWORD(reader).value
		self.ImageBase                   = DWORD(reader).value
		self.SectionAlignment            = DWORD(reader).value
		self.FileAlignment               = DWORD(reader).value
		self.MajorOperatingSystemVersion = WORD(reader).value
		self.MinorOperatingSystemVersion = WORD(reader).value
		self.MajorImageVersion           = WORD(reader).value
		self.MinorImageVersion           = WORD(reader).value
		self.MajorSubsystemVersion       = WORD(reader).value
		self.MinorSubsystemVersion       = WORD(reader).value
		self.Win32VersionValue           = DWORD(reader).value
		self.SizeOfImage                 = DWORD(reader).value
		self.SizeOfHeaders               = DWORD(reader).value
		self.CheckSum                    = DWORD(reader).value
		self.Subsystem                   = WORD(reader).value
		self.DllCharacteristics          = WORD(reader).value
		self.SizeOfStackReserve          = DWORD(reader).value
		self.SizeOfStackCommit           = DWORD(reader).value
		self.SizeOfHeapReserve           = DWORD(reader).value
		self.SizeOfHeapCommit            = DWORD(reader).value
		self.LoaderFlags                 = DWORD(reader).value
		self.NumberOfRvaAndSizes         = DWORD(reader).value
		self.DataDirectory               = [IMAGE_DATA_DIRECTORY(reader) for _ in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]

class IMAGE_NT_HEADERS:
	def __init__(self, reader):
		self.Signature     = DWORD(reader).value
		self.FileHeader    = IMAGE_FILE_HEADER(reader)
		if self.FileHeader.Machine == IMAGE_FILE_MACHINE_I386:
			self.OptionalHeader = IMAGE_OPTIONAL_HEADER32(reader)
		else:
			self.OptionalHeader = IMAGE_OPTIONAL_HEADER64(reader)

IMAGE_RESOURCE_DIRECTORY_SIZE = 16
class IMAGE_RESOURCE_DIRECTORY:
	def __init__(self, reader):
		self.Characteristics      = DWORD(reader).value
		self.TimeDateStamp        = DWORD(reader).value
		self.MajorVersion         = WORD(reader).value
		self.MinorVersion         = WORD(reader).value
		self.NumberOfNamedEntries = WORD(reader).value
		self.NumberOfIdEntries    = WORD(reader).value

IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8
class IMAGE_RESOURCE_DIRECTORY_ENTRY:
	def __init__(self, reader):
		self.Name           = DWORD(reader).value
		self.OffsetToData   = DWORD(reader).value

	@property
	def NameOffset(self):
		return self.Name & 0x7FFFFFFF

	@property
	def NameIsString(self):
		return (self.Name >> 31) & 1

	@property
	def Id(self):
		return self.Name & 0xFFFF

	@property
	def OffsetToDirectory(self):
		return self.OffsetToData & 0x7FFFFFFF

	@property
	def DataIsDirectory(self):
		return (self.OffsetToData >> 31) & 1
	
class IMAGE_RESOURCE_DATA_ENTRY:
	def __init__(self, reader):
		self.OffsetToData = DWORD(reader).value
		self.Size         = DWORD(reader).value
		self.CodePage     = DWORD(reader).value
		self.Reserved     = DWORD(reader).value

class VS_FIXEDFILEINFO:
	def __init__(self, reader):
		self.dwSignature      = DWORD(reader).value
		self.dwStrucVersion   = DWORD(reader).value
		self.dwFileVersionMS  = DWORD(reader).value
		self.dwFileVersionLS  = DWORD(reader).value
		self.dwProductVersionMS = DWORD(reader).value
		self.dwProductVersionLS = DWORD(reader).value
		self.dwFileFlagsMask  = DWORD(reader).value
		self.dwFileFlags      = DWORD(reader).value
		self.dwFileOS         = DWORD(reader).value
		self.dwFileType       = DWORD(reader).value
		self.dwFileSubtype    = DWORD(reader).value
		self.dwFileDateMS     = DWORD(reader).value
		self.dwFileDateLS     = DWORD(reader).value

class VS_VERSIONINFO:
	def __init__(self, reader):
		self.wLength      = WORD(reader).value
		self.wValueLength = WORD(reader).value
		self.wType        = WORD(reader).value
		self.szKey        = reader.read(32)
		self.Padding1     = WORD(reader).value
		self.Value        = VS_FIXEDFILEINFO(reader)
		self.Padding2     = WORD(reader).value
		self.Children     = WORD(reader).value