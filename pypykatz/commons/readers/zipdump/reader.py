#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import zipfile
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

from pypykatz import logger
import sys
import copy
import platform
import os
import ntpath
import json

class Module:
	def __init__(self):
		self.name = None
		self.baseaddress = None
		self.size = None
		self.endaddress = None
		self.pages = []
		
		self.versioninfo = None
		self.checksum = None
		self.timestamp = None
		
	def inrange(self, addr):
		return self.baseaddress <= addr < self.endaddress
	
	@staticmethod
	def parse(name, baseAddr, baseSize, timestamp):
		m = Module()
		m.name = name
		m.baseaddress = baseAddr
		m.size = baseSize
		m.endaddress = m.baseaddress + m.size
		
		m.timestamp = timestamp
		
		return m
		
	def __str__(self):
		return '%s %s %s %s %s' % (self.name, hex(self.baseaddress), hex(self.size), hex(self.endaddress), self.timestamp )
		
class Page:
	def __init__(self):
		self.fileobj = None
		self.BaseAddress = None
		self.AllocationBase  = None
		self.AllocationProtect  = None
		self.RegionSize  = None
		self.EndAddress = None
		
		self.data = None
	
	@staticmethod
	def parse(fileobj, BaseAddress, AllocationBase, RegionSize = None, AllocationProtect = 0):
		p = Page()
		p.fileobj = fileobj
		p.BaseAddress = BaseAddress
		p.AllocationBase  = AllocationBase
		p.AllocationProtect  = AllocationProtect
		p.RegionSize  = min(RegionSize, 100*1024*1024) # TODO: need this currently to stop infinite search
		p.EndAddress  = BaseAddress + RegionSize
		return p
		
	def read_data(self):
		if self.data is not None:
			return
		self.fileobj.seek(0)
		self.data = self.fileobj.read()
		self.fileobj = None
		
	def inrange(self, addr):
		return self.BaseAddress <= addr < self.EndAddress
		
	def search(self, pattern):
		if len(pattern) > self.RegionSize:
			return []
		self.read_data()
		data = copy.deepcopy(self.data)
		fl = []
		offset = 0
		while len(data) > len(pattern):
			marker = data.find(pattern)
			if marker == -1:
				return fl
			fl.append(marker + offset + self.BaseAddress)
			data = data[marker+1:]
			offset += marker + 1
				
		return fl
	
	def __str__(self):
		return '0x%08x 0x%08x %s 0x%08x' % (self.BaseAddress, self.AllocationBase, self.AllocationProtect, self.RegionSize)



		
class BufferedZipDumpReader:
	def __init__(self, reader):
		self.reader = reader
		self.pages = []
		
		self.current_segment = None
		self.current_position = None
		
	def _select_segment(self, requested_position):
		"""
		
		"""
		# check if we have semgnet for requested address in cache
		for page in self.pages:
			if page.inrange(requested_position):
				self.current_segment = page
				self.current_position = requested_position
				return
		
		# not in cache, check if it's present in memory space. if yes then create a new buffered memeory object, and copy data
		for page in self.reader.pages:
			if page.inrange(requested_position):
				page.read_data()
				newsegment = copy.deepcopy(page)
				self.pages.append(newsegment)
				self.current_segment = newsegment
				self.current_position = requested_position
				return
				
		raise Exception('Memory address 0x%08x is not in process memory space' % requested_position)

	def get_reader(self):
		return self.reader

	def seek(self, offset, whence = 0):
		"""
		Changes the current address to an offset of offset. The whence parameter controls from which position should we count the offsets.
		0: beginning of the current memory segment
		1: from current position
		2: from the end of the current memory segment
		If you wish to move out from the segment, use the 'move' function
		"""
		if whence == 0:
			t = self.current_segment.BaseAddress + offset
		elif whence == 1:
			t = self.current_position + offset
		elif whence == 2:
			t = self.current_segment.EndAddress - offset
		else:
			raise Exception('Seek function whence value must be between 0-2')
			
		if not self.current_segment.inrange(t):
			raise Exception('Seek would cross memory segment boundaries (use move)')
		
		self.current_position = t
		return
		
	def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		self._select_segment(address)
		return
		
	def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
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
		if not self.current_segment.inrange(t):
			raise Exception('Would read over segment boundaries!')
		return self.current_segment.data[self.current_position - self.current_segment.BaseAddress :t - self.current_segment.BaseAddress]
	
	def read(self, size = -1):
		"""
		Returns data bytes of size size from the current segment. If size is -1 it returns all the remaining data bytes from memory segment
		"""
		if size < -1:
			raise Exception('You shouldnt be doing this')
		if size == -1:
			t = self.current_segment.remaining_len(self.current_position)
			if not t:
				return None
			
			old_new_pos = self.current_position
			self.current_position = self.current_segment.EndAddress
			return self.current_segment.data[old_new_pos - self.current_segment.BaseAddress:]
		
		t = self.current_position + size
		if not self.current_segment.inrange(t):
			raise Exception('Would read over segment boundaries!')
		
		old_new_pos = self.current_position
		self.current_position = t		
		return self.current_segment.data[old_new_pos - self.current_segment.BaseAddress :t - self.current_segment.BaseAddress]
	
	def read_int(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = True)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = True)
	
	def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = False)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = False)
	
	def find(self, pattern):
		"""
		Searches for a pattern in the current memory segment
		"""
		pos = self.current_segment.data.find(pattern)
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
			last_found = self.current_segment.data.find(pattern, last_found + 1)
			if last_found == -1:
				break
			pos.append(last_found + self.current_segment.start_address)
			
		return pos
		
	def find_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns the first occurrence.
		This is exhaustive!
		"""
		pos_s = self.reader.search(pattern)
		if len(pos_s) == 0:
			return -1
		
		return pos_s[0]
		
	def find_all_global(self, pattern, allocationprotect = 0x04):
		"""
		Searches for the pattern in the whole process memory space and returns a list of addresses where the pattern begins.
		This is exhaustive!
		"""
		return self.reader.search(pattern, allocationprotect = allocationprotect)
		
	def get_ptr(self, pos):
		self.move(pos)
		return self.read_uint()
		#raw_data = self.read(pos, self.sizeof_ptr)
		#return struct.unpack(self.unpack_ptr, raw_data)[0]
	
	def get_ptr_with_offset(self, pos):
		if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
			self.move(pos)
			ptr = int.from_bytes(self.read(4), byteorder = 'little', signed = True)
			return pos + 4 + ptr
		else:
			self.move(pos)
			return self.read_uint()
	
	def find_in_module(self, module_name, pattern, find_first = False, reverse_order = False):
		t = self.reader.search_module(module_name, pattern, find_first = find_first, reverse_order = reverse_order)
		return t
		
		
class ZipDumpReader:
	def __init__(self):
		self.zipobj = None
		self.sysinfo = None
		self.processor_architecture = None
		self.current_position = None
		self.BuildNumber = None
		self.modules = []
		self.pages = []
		
		self.msv_dll_timestamp = 0 #a special place in our hearts....
	
	@staticmethod
	def from_file(filename):
		reader = ZipDumpReader()
		reader.zipobj = zipfile.ZipFile(filename, 'r')
		reader.setup()
		return reader
		
	def setup(self):
		with self.zipobj.open("sysinfo.json") as f:
			self.sysinfo = json.load(f)
		
		print(self.sysinfo)
		self.processor_architecture = PROCESSOR_ARCHITECTURE(self.sysinfo['sysInfo']['Architecture'])
		
		logger.log(1, 'Getting build number')
		self.BuildNumber = int(self.sysinfo['sysInfo']['BuildNumber'])

		timestamp = 0

		for module in self.sysinfo['modules']:
			self.modules.append(
				Module.parse(
					module['exePath'], 
					module['baseAddr'],
					module['baseSize'],
					timestamp
				)
			)
			
		logger.log(1, 'Found %d modules' % len(self.modules))

		for filename in self.zipobj.namelist():
			if filename.endswith('.bin') is False:
				continue

			BaseAddress = int(filename[:-4], 16)
			RegionSize = self.zipobj.getinfo(filename).file_size
			
			self.pages.append(Page.parse(self.zipobj.open(filename), BaseAddress, BaseAddress, RegionSize))		
		
		for page in self.pages:
			for mod in self.modules:
				if mod.inrange(page.BaseAddress) == True:
					mod.pages.append(page)

	def get_handler(self):
		return self.process_handle

	def get_memory(self, allocationprotect = 0x04):
		t = []
		for page in self.pages:
			if page.AllocationProtect & allocationprotect:
				t.append(page)
		return t

	def get_buffered_reader(self):
		return BufferedZipDumpReader(self)			
		
	def get_module_by_name(self, module_name):
		for mod in self.modules:
			if mod.name.lower().find(module_name.lower()) != -1:
				return mod
		return None	
	
	def search_module(self, module_name, pattern, find_first = False, reverse_order = False):
		mod = self.get_module_by_name(module_name)
		if mod is None:
			raise Exception('Could not find module! %s' % module_name)
		needles = []
		for page in mod.pages:
			needles += page.search(pattern)
			if len(needles) > 0 and find_first is True:
				return needles

		return needles

	def search(self, pattern, allocationprotect = 0x04):
		t = []
		for page in self.pages:
			if page.AllocationProtect & allocationprotect:
				t += page.search(pattern)
		return t
		
if __name__ == '__main__':
	logger.basicConfig(level=1)
	lr = ZipDumpReader()
	blr = lr.get_buffered_reader()
	
	blr.move(0x1000)
	