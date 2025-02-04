import traceback
import enum
import json
import datetime
import base64

from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

def geterr(err:Exception):
	t = str(err) + '\r\n'
	for line in traceback.format_tb(err.__traceback__):
		t += line
	return t

class KatzSystemArchitecture(enum.Enum):
	X86 = enum.auto()
	X64 = enum.auto()

class GenericReader:
	def __init__(self, data, processor_architecture = KatzSystemArchitecture.X64):
		"""
		data is bytes
		"""	
		self.processor_architecture = processor_architecture
		self.start_address = 0
		self.end_address = len(data)
		self.size = len(data)
		self.data = data
		self.current_position = 0
		
	def inrange(self, ptr):
		return self.start_address <= ptr <= self.end_address
		
	def seek(self, offset, whence = 0):
		"""
		Changes the current address to an offset of offset. The whence parameter controls from which position should we count the offsets.
		0: beginning of the current memory segment
		1: from current position
		2: from the end of the current memory segment
		If you wish to move out from the segment, use the 'move' function
		"""
		if whence == 0:
			t = self.start_address + offset
		elif whence == 1:
			t = self.current_position + offset
		elif whence == 2:
			t = self.end_address - offset
		else:
			raise Exception('Seek function whence value must be between 0-2')
			
		if not self.inrange(t):
			raise Exception('Seek would point out of buffer')
		
		self.current_position = t
		return
		
	def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		self.seek(address)
		return
		
	def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.processor_architecture == KatzSystemArchitecture.X64:
				alignment = 8
			else:
				alignment = 4
		offset = self.current_position % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		self.seek(offset_to_aligned, 1)
		return
		
	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.current_position
		
	def peek(self, length):
		"""
		Returns up to length bytes from the current memory segment
		"""
		t = self.current_position + length
		if not self.inrange(t):
			raise Exception('Would read out of buffer!')
		return self.data[self.current_position - self.start_address :t - self.start_address]
	
	def read(self, size = -1):
		"""
		Returns data bytes of size size from the current segment. If size is -1 it returns all the remaining data bytes from memory segment
		"""
		if size < -1:
			raise Exception('You shouldnt be doing this')
		if size == -1:
			oldnew_pos = self.current_position
			self.current_position = self.end_address
			return self.data[oldnew_pos:]
		
		t = self.current_position + size
		if not self.inrange(t):
			raise Exception('Would read out of buffer!')
		
		old_new_pos = self.current_position
		self.current_position = t		
		return self.data[old_new_pos:t]
	
	def read_int(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.processor_architecture == KatzSystemArchitecture.X64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = True)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = True)
	
	def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.processor_architecture == KatzSystemArchitecture.X64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = False)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = False)
	
	def find(self, pattern):
		"""
		Searches for a pattern in the current memory segment
		"""
		pos = self.data.find(pattern)
		if pos == -1:
			return -1
		return pos + self.current_position
		
	def find_all(self, pattern):
		"""
		Searches for all occurrences of a pattern in the current memory segment, returns all occurrences as a list
		"""
		pos = []
		last_found = -1
		while True:
			last_found = self.data.find(pattern, last_found + 1)
			if last_found == -1:
				break
			pos.append(last_found + self.start_address)
			
		return pos
		
	def get_ptr(self, pos):
		self.move(pos)
		return self.read_uint()
		#raw_data = self.read(pos, self.sizeof_ptr)
		#return struct.unpack(self.unpack_ptr, raw_data)[0]
	
	def get_ptr_with_offset(self, pos):
		if self.processor_architecture == KatzSystemArchitecture.X64:
			self.move(pos)
			ptr = int.from_bytes(self.read(4), byteorder = 'little', signed = True)
			return pos + 4 + ptr
			#raw_data = self.read(pos, self.sizeof_long)
			#ptr = struct.unpack(self.unpack_long, raw_data)[0]
			#return pos + self.sizeof_long + ptr
		else:
			self.move(pos)
			return self.read_uint()
			#raw_data = self.read(pos, self.sizeof_long)
			#return struct.unpack(self.unpack_long, raw_data)[0]

class AGenericReader:
	def __init__(self, data, processor_architecture = KatzSystemArchitecture.X64):
		"""
		data is bytes
		"""	
		self.processor_architecture = processor_architecture
		self.start_address = 0
		self.end_address = len(data)
		self.size = len(data)
		self.data = data
		self.current_position = 0
		
	def inrange(self, ptr):
		return self.start_address <= ptr <= self.end_address
		
	async def seek(self, offset, whence = 0):
		"""
		Changes the current address to an offset of offset. The whence parameter controls from which position should we count the offsets.
		0: beginning of the current memory segment
		1: from current position
		2: from the end of the current memory segment
		If you wish to move out from the segment, use the 'move' function
		"""
		if whence == 0:
			t = self.start_address + offset
		elif whence == 1:
			t = self.current_position + offset
		elif whence == 2:
			t = self.end_address - offset
		else:
			raise Exception('Seek function whence value must be between 0-2')
			
		if not self.inrange(t):
			raise Exception('Seek would point out of buffer')
		
		self.current_position = t
		return
		
	async def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		await self.seek(address)
		return
		
	async def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.processor_architecture == KatzSystemArchitecture.X64:
				alignment = 8
			else:
				alignment = 4
		offset = self.current_position % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		await self.seek(offset_to_aligned, 1)
		return
		
	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.current_position
		
	async def peek(self, length):
		"""
		Returns up to length bytes from the current memory segment
		"""
		t = self.current_position + length
		if not self.inrange(t):
			raise Exception('Would read out of buffer!')
		return self.data[self.current_position - self.start_address :t - self.start_address]
	
	async def read(self, size = -1):
		"""
		Returns data bytes of size size from the current segment. If size is -1 it returns all the remaining data bytes from memory segment
		"""
		if size < -1:
			raise Exception('You shouldnt be doing this')
		if size == -1:
			oldnew_pos = self.current_position
			self.current_position = self.end_address
			return self.data[oldnew_pos:]
		
		t = self.current_position + size
		if not self.inrange(t):
			raise Exception('Would read out of buffer!')
		
		old_new_pos = self.current_position
		self.current_position = t		
		return self.data[old_new_pos:t]
	
	async def read_int(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.processor_architecture == KatzSystemArchitecture.X64:
			t = await self.read(8)
			return int.from_bytes(t, byteorder = 'little', signed = True)
		else:
			t = await self.read(4)
			return int.from_bytes(t, byteorder = 'little', signed = True)
	
	async def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.processor_architecture == KatzSystemArchitecture.X64:
			t = await self.read(8)
			return int.from_bytes(t, byteorder = 'little', signed = False)
		else:
			t = await self.read(4)
			return int.from_bytes(t, byteorder = 'little', signed = False)
	
	async def find(self, pattern):
		"""
		Searches for a pattern in the current memory segment
		"""
		pos = await self.data.find(pattern)
		if pos == -1:
			return -1
		return pos + self.current_position
		
	async def find_all(self, pattern):
		"""
		Searches for all occurrences of a pattern in the current memory segment, returns all occurrences as a list
		"""
		pos = []
		last_found = -1
		while True:
			last_found = await self.data.find(pattern, last_found + 1)
			if last_found == -1:
				break
			pos.append(last_found + self.start_address)
			
		return pos
		
	async def get_ptr(self, pos):
		await self.move(pos)
		return await self.read_uint()
		#raw_data = self.read(pos, self.sizeof_ptr)
		#return struct.unpack(self.unpack_ptr, raw_data)[0]
	
	async def get_ptr_with_offset(self, pos):
		if self.processor_architecture == KatzSystemArchitecture.X64:
			await self.move(pos)
			ptr = int.from_bytes(self.read(4), byteorder = 'little', signed = True)
			return pos + 4 + ptr
			#raw_data = self.read(pos, self.sizeof_long)
			#ptr = struct.unpack(self.unpack_long, raw_data)[0]
			#return pos + self.sizeof_long + ptr
		else:
			await self.move(pos)
			return await self.read_uint()
			#raw_data = self.read(pos, self.sizeof_long)
			#return struct.unpack(self.unpack_long, raw_data)[0]
		
		
		
class WindowsBuild(enum.Enum):
	WIN_XP  = 2600
	WIN_2K3 = 3790
	WIN_VISTA = 6000
	WIN_7 = 7600
	WIN_8 = 9200
	WIN_BLUE = 9600
	WIN_10_1507 = 10240
	WIN_10_1511 = 10586
	WIN_10_1607 = 14393
	WIN_10_1703 = 15063
	WIN_10_1709 = 16299
	WIN_10_1803 = 17134
	WIN_10_1809 = 17763
	WIN_10_1903 = 18362
	WIN_10_1909 = 18363
	WIN_10_2004 = 19041
	WIN_10_20H2 = 19042
	WIN_11_2022 = 20348
	WIN_11_2023 = 22621
	WIN_11_23H2 = 22631

class WindowsMinBuild(enum.Enum):
	WIN_XP = 2500
	WIN_2K3 = 3000
	WIN_VISTA = 5000
	WIN_7 = 7000
	WIN_8 = 8000
	WIN_BLUE = 9400
	WIN_10 = 9800
	WIN_11 = 22000
	
	
def hexdump( src, length=16, sep='.', start = 0):
	'''
	@brief Return {src} in hex dump.
	@param[in] length	{Int} Nb Bytes by row.
	@param[in] sep		{Char} For the text part, {sep} will be used for non ASCII char.
	@return {Str} The hexdump

	@note Full support for python2 and python3 !
	'''
	result = []
	if src is None:
		return ''

	# Python3 support
	try:
		xrange(0,1)
	except NameError:
		xrange = range

	for i in xrange(0, len(src), length):
		subSrc = src[i:i+length]
		hexa = ''
		isMiddle = False
		for h in xrange(0,len(subSrc)):
			if h == length/2:
				hexa += ' '
			h = subSrc[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x','')
			if len(h) == 1:
				h = '0'+h
			hexa += h+' '
		hexa = hexa.strip(' ')
		text = ''
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c)
			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep
		if start == 0:
			result.append(('%08x:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text))
		else:
			result.append(('%08x(+%04x):  %-'+str(length*(2+1)+1)+'s  |%s|') % (start+i, i, hexa, text))
	return '\n'.join(result)
	
class UniversalEncoder(json.JSONEncoder):
	"""
	Used to override the default json encoder to provide a direct serialization for formats
	that the default json encoder is incapable to serialize
	"""
	def default(self, obj):
		if isinstance(obj, datetime.datetime):
			return obj.isoformat()
		elif isinstance(obj, enum.Enum):
			return obj.value
		elif isinstance(obj, bytes):
			return obj.hex()
		#elif getattr(obj, "to_json", None):
		#	to_json = getattr(obj, "to_json", None)
		#	if callable(to_json):
		#		return obj.to_json()
		elif getattr(obj, "to_dict", None):
			to_dict = getattr(obj, "to_dict", None)
			if callable(to_dict):
				return obj.to_dict()
		
		else:
			return json.JSONEncoder.default(self, obj)


	

class KatzSystemInfo:
	def __init__(self):
		self.architecture = None
		self.buildnumber = None
		self.msv_dll_timestamp = None #this is needed :(
		self.operating_system = None
		self.major_version = 6
		
	def __str__(self):
		return 'ARCH:%s BUILD:%s MSV_TS:%s OS(guess): %s' % (self.architecture.name, self.buildnumber, self.msv_dll_timestamp, self.operating_system)
	
	@staticmethod
	def from_live_reader(lr):
		sysinfo = KatzSystemInfo()
		if lr.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
			sysinfo.architecture = KatzSystemArchitecture.X64
		elif lr.processor_architecture == PROCESSOR_ARCHITECTURE.INTEL:
			sysinfo.architecture = KatzSystemArchitecture.X86
			
		sysinfo.buildnumber = lr.BuildNumber
		
		sysinfo.msv_dll_timestamp = lr.msv_dll_timestamp	
		return sysinfo
		
	@staticmethod
	def from_minidump(minidump):
		sysinfo = KatzSystemInfo()
		if minidump.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			sysinfo.architecture = KatzSystemArchitecture.X64
		elif minidump.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
			sysinfo.architecture = KatzSystemArchitecture.X86
		
		sysinfo.operating_system = minidump.sysinfo.OperatingSystem
		sysinfo.buildnumber = minidump.sysinfo.BuildNumber
		
		sysinfo.msv_dll_timestamp = 0
		for module in minidump.modules.modules:
			if module.name.find('lsasrv.dll') != -1:
				sysinfo.msv_dll_timestamp = module.timestamp
	
		return sysinfo

	@staticmethod
	def from_rekallreader(rekallreader):
		sysinfo = KatzSystemInfo()
		sysinfo.architecture = rekallreader.processor_architecture		
		sysinfo.operating_system = None
		sysinfo.buildnumber = rekallreader.BuildNumber
		sysinfo.msv_dll_timestamp = rekallreader.msv_dll_timestamp
	
		return sysinfo


def base64_decode_url(value: str, bytes_expected=False) -> str:
	padding = 4 - (len(value) % 4)
	value = value + ("=" * padding)
	result = base64.urlsafe_b64decode(value)
	if bytes_expected is True:
		return result
	return result.decode()
