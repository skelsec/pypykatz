import io
import enum
import logging
from minidump.win_datatypes import *

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
		
# https://msdn.microsoft.com/en-us/library/windows/hardware/ff540605(v=vs.85).aspx
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
		