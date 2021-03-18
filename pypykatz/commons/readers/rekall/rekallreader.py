#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# Kudos:
#  Buherator (@buherator) for helping me navigate the Peb
#

import logging

from pypykatz.pypykatz import pypykatz
from pypykatz.commons.common import *

from . import *

class RekallModule:
	def __init__(self):
		self.name = None
		self.start_addr = None
		self.end_addr = None
		self.size = None

	@staticmethod
	def from_module(module):
		rm = RekallModule()
		rm.name = str(module.BaseDllName).lower()
		rm.start_addr = int(module.DllBase)
		rm.size = int(module.SizeOfImage)
		rm.end_addr = rm.start_addr + rm.size
		return rm

class RekallReader:
	def __init__(self, timestamp_override = None, buildnumber = None):
		"""
		Timestamp override will change the msv_dll_timestamp value.
		If None > no change
		If 0 > it disables the ANIT_MIMIKATZ structs on certain builds
		If 1 > it enforces to use the ANTI_MIMIKATZ structs on certain builds
		"""
		
		self.session = None
		self.lsass_task = None
		self.cc = None
		self.task_as = None
		self.cur_pos = None
		self.modules = {}
		
		self.timestamp_override = timestamp_override
		#needed for pypykatz
		self.processor_architecture = None
		self.BuildNumber = buildnumber
		self.msv_dll_timestamp = None #a special place in our hearts....

		
	def setup(self):
		self.cc = self.session.plugins.cc()
		self.search_lsass()
		self.task_as = self.lsass_task.get_process_address_space()
		self.processor_architecture = self.get_arch()
		if not self.BuildNumber:
			self.BuildNumber = self.get_buildnumber()
		
		if self.timestamp_override:
			if self.timestamp_override == 0:
				sysinfo.msv_dll_timestamp = 0x53480000 - 1
			elif self.timestamp_override == 1:
				sysinfo.msv_dll_timestamp = 0x53480000 + 1
		
		self.load_modules()

	@staticmethod
	def from_memory_file(memory_file, timestamp_override = None, buildnumber = None):
		logging.info('Invoking recall on file %s' % memory_file)
		rsession = session.Session(
			filename = memory_file,
			autodetect=['rsds', 'pe', 'windows_kernel_file'],
			logger = logging.getLogger('pypykatz'),
			autodetect_build_local = 'full',
			autodetect_scan_length=10*1024*1024*1024,
			profile_path=["https://github.com/google/rekall-profiles/raw/master", "http://profiles.rekall-forensic.com"]
			)

		return RekallReader.from_session(rsession, timestamp_override, buildnumber)


	@staticmethod
	def from_session(session, timestamp_override = None, buildnumber = None):
		rr = RekallReader(timestamp_override, buildnumber)
		rr.session = session
		rr.setup()
		return rr

	def get_buildnumber(self):
		return int(self.lsass_task.Peb.OSBuildNumber)

	def get_arch(self):
		if self.session.profile.metadata("arch")[-2:] == '64':
			return KatzSystemArchitecture.X64
		return KatzSystemArchitecture.X86

	def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.processor_architecture == KatzSystemArchitecture.X64:
				alignment = 8
			else:
				alignment = 4
		offset = self.cur_pos % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		self.read(offset_to_aligned)
		return

	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.cur_pos

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

	def get_ptr(self, pos):
		self.move(pos)
		return self.read_uint()

	def get_ptr_with_offset(self, pos):
		if self.processor_architecture == KatzSystemArchitecture.X64:
			self.move(pos)
			ptr = int.from_bytes(self.read(4), byteorder = 'little', signed = True)
			return pos + 4 + ptr
		else:
			self.move(pos)
			return self.read_uint()


	def move(self, pos):
		self.cur_pos = pos

	def read(self, size):
		data = self.task_as.read(self.cur_pos, size)
		self.cur_pos += size
		return data

	def peek(self, size):
		return self.task_as.read(self.cur_pos, size)

	def load_modules(self):
		self.task_as = self.lsass_task.get_process_address_space()
		for module in self.lsass_task.get_load_modules():
			self.modules[str(module.BaseDllName).lower()] = RekallModule.from_module(module)
			if str(module.BaseDllName).lower() == 'msv1_0.dll':
				self.msv_dll_timestamp = int(module.TimeDateStamp)
				if self.msv_dll_timestamp == 0:
					self.session.logging.info('WARNING! msv.dll timestamp not found! This could cause errors with older windows builds. You might need to specify it manually for anti_mimikatz structs!')
					self.msv_dll_timestamp = 0

	def search_lsass(self):
		self.session.logging.info('Searching LSASS process')
		tasks = []
		for task in self.session.plugins.pslist(proc_regex='lsass.exe').filter_processes():
			tasks.append(task)

		if len(tasks) > 1:
			self.session.logging.info('WARNING! Multiple processes matched the filter!! Using first one!')

		if len(tasks) == 0:
			raise Exception('LSASS.exe not found!')

		self.lsass_task = tasks[0]
		self.cc.SwitchProcessContext(self.lsass_task)

	def load_module(self, module_name):
		for module in self.lsass_task.get_load_modules():
			#print(module.BaseDllName)
			process_offset = self.task_as.vtop(self.lsass_task.obj_offset)
			if not process_offset:
				raise Exception('Cant get module! %s' % module_name)
			if str(module.BaseDllName).lower() != module_name:
				continue
			else:
				self.session.logging.info('Found module!')
				return module
			

	def find_in_module(self, module_name, pattern, find_first = False, reverse_order = False):
		if module_name.lower() not in self.modules:
			raise Exception('Module is not in lsass emmory space! %s' % module_name)
		module = self.modules[module_name.lower()]
		res = []
		scanner = rekall.scan.MultiStringScanner(
			needles=[pattern],
			address_space=self.lsass_task.get_process_address_space()
			)
		self.session.logging.info('module.start_addr %s' % module.start_addr)
		for hit, _ in scanner.scan(offset=int(module.start_addr), maxlen=int(module.size)):
			res.append(int(hit))
		return res

if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)
	memory_file = 'memory.dmp'
	reader = RekallReader(memory_file)
	print(reader.session.profile.metadata("arch"))
	#reader.search_module('lsasrv.dll', b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15')
	sysinfo = KatzSystemInfo.from_rekallreader(reader)
	print(sysinfo.architecture)
	p = pypykatz.pypykatz(reader, sysinfo)
	mimi = p.start()
	for luid in p.logon_sessions:
		print(str(p.logon_sessions[luid]))
	print('Done!')
