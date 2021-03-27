#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
#
# This file contains a reader implementation to interface pypykatz lsass parsing module with volatility3
# One would need to install volatility3 and drop the plugin file (separate project) to the appropriate volatility3 plugins folder
# The reason why the reader code is not in the plugin folder is that in case pypykatz plugin becomes official in vol3, I don't wish to administer changes via PR to the vol3 team
# they probably have more important things to deal with :)
#

import logging

from pypykatz.pypykatz import pypykatz
from pypykatz.commons.common import *

from . import *


class VOL3Section:
	def __init__(self):
		self.start = None
		self.end = None
		self.size = None

	@staticmethod
	def from_vad(vad):
		s = VOL3Section()
		s.start = int(vad.get_start())
		s.end = int(vad.get_end())
		s.size = s.end - s.start
		return s

class VOL3Module:
	def __init__(self):
		self.name = None
		self.start_addr = None
		self.end_addr = None
		self.size = None

	@staticmethod
	def from_module(BaseDllName, FullDllName, entry):
		rm = VOL3Module()
		rm.name = str(BaseDllName).lower()
		rm.start_addr = int(entry.DllBase)
		rm.size = int(entry.SizeOfImage)
		rm.end_addr = rm.start_addr + rm.size
		return rm

class VOL3Sysinfo:
	def __init__(self):
		self.architecture = None
		self.buildnumber = None
		self.msv_dll_timestamp = 0x53480000 + 1
		self.operating_system = None
		self.major_version = 6

class Vol3Reader:
	def __init__(self, vol_obj):
		self.vol_obj = vol_obj
		self.proc_layer_name = None
		self.proc_layer = None
		self.lsass_process = None
		self.modules = {}
		self.sections = []
		self.processor_architecture = None

		self.setup()

	def setup(self):
		self.find_lsass()
		self.list_dlls()
		self.get_buildnumber()
		self.list_sections()
		self.get_arch()

	def get_sysinfo(self):
		sysinfo = KatzSystemInfo()
		sysinfo.architecture = self.processor_architecture
		sysinfo.buildnumber = self.buildnumber
		sysinfo.msv_dll_timestamp = 0x53480000 + 1
		sysinfo.operating_system = None
		sysinfo.major_version = 6 #TODO: add majorversion check option
		return sysinfo

	def find_lsass(self):
		filter_func = pslist.PsList.create_name_filter(['lsass.exe'])
		for proc in pslist.PsList.list_processes(
					context = self.vol_obj.context,
					layer_name = self.vol_obj.config['primary'],
					symbol_table = self.vol_obj.config['nt_symbols'],
					filter_func = filter_func
				):
			self.lsass_process = proc
			self.proc_layer_name = self.lsass_process.add_process_layer()
			self.proc_layer = self.vol_obj.context.layers[self.proc_layer_name]
			return

		raise Exception('LSASS process not found!')

	def list_dlls(self):
		#https://github.com/volatilityfoundation/volatility3/blob/master/volatility/framework/plugins/windows/dlllist.py
		for entry in self.lsass_process.load_order_modules():
			BaseDllName = FullDllName = renderers.UnreadableValue()
			try:
				BaseDllName = entry.BaseDllName.get_string()
				# We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
				FullDllName = entry.FullDllName.get_string()
			except exceptions.InvalidAddressException:
				pass
			
			module = VOL3Module.from_module(BaseDllName, FullDllName, entry)
			self.modules[module.name] = module

	def get_buildnumber(self):
		# https://github.com/volatilityfoundation/volatility3/blob/ee31ece0062ce762ed38f6d0a1c54e9f1cd37970/volatility/framework/plugins/windows/cmdline.py
		peb = self.vol_obj.context.object(
		    self.vol_obj.config["nt_symbols"] + constants.BANG + "_PEB",
		    layer_name = self.proc_layer_name,
		    offset = self.lsass_process.Peb
		)
		self.buildnumber = peb.OSBuildNumber

	def list_sections(self):
		# not entirely sure if this is needed...
		#https://github.com/volatilityfoundation/volatility3/blob/9af7fbb48ddaa2fb9c74754b8a95e77c66533bf1/volatility/framework/plugins/windows/vadinfo.py#L82
		for vad in self.lsass_process.get_vad_root().traverse():
			self.sections.append(VOL3Section.from_vad(vad))

	def get_arch(self):
		if not symbols.symbol_table_is_64bit(self.vol_obj.context, self.vol_obj.config["nt_symbols"]):
			self.processor_architecture = KatzSystemArchitecture.X86
		self.processor_architecture = KatzSystemArchitecture.X64

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
		data = self.proc_layer.read(self.cur_pos, size, pad = False)
		self.cur_pos += size
		return data

	def peek(self, size):
		return self.proc_layer.read(self.cur_pos, size)

	def find_in_module(self, module_name, pattern, find_first = False, reverse_order = False):
		if module_name.lower() not in self.modules:
			raise Exception('Module is not in lsass memory space! %s' % module_name)
		module = self.modules[module_name.lower()]
		res = []
		scanner = MultiStringScanner(patterns=[pattern])
		sections = [(int(module.start_addr), int(module.size))]
		for hit, _ in self.proc_layer.scan(
			context = self.vol_obj.context, 
			scanner = scanner,
			sections = sections
			): 
			res.append(int(hit))
		return res


def vol3_generator(mimi):
	for luid in mimi.logon_sessions:
		for row in mimi.logon_sessions[luid].to_grep_rows():
			yield 0, row
	for cred in mimi.orphaned_creds:
		t = cred.to_dict()
		if t['credtype'] != 'dpapi':
			if t['password'] is not None:
				x =  [str(t['credtype']), str(t['domainname']), str(t['username']), '', '', '', '', '', str(t['password']), '']
				yield 0, x
		else:
			t = cred.to_dict()
			x = [str(t['credtype']), '', '', '', '', '', str(t['masterkey']), str(t['sha1_masterkey']), str(t['key_guid']), '']
			yield 0, x

def vol3_treegrid(mimi):
	return renderers.TreeGrid([
			("credtype", str),
			("domainname", str),
			("username", str),
			("NThash", str),
			("LMHash", str),
			("SHAHash", str),
			("masterkey", str),
			("masterkey(sha1)", str),
			("key_guid", str),
			("password", str),         
		], vol3_generator(mimi))
