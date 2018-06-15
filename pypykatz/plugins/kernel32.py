#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2016, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


from .defines import *

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD            = 0x100
PAGE_NOCACHE          = 0x200
PAGE_WRITECOMBINE     = 0x400
MEM_COMMIT           = 0x1000
MEM_RESERVE          = 0x2000
MEM_DECOMMIT         = 0x4000
MEM_RELEASE          = 0x8000
MEM_FREE            = 0x10000
MEM_PRIVATE         = 0x20000
MEM_MAPPED          = 0x40000
MEM_RESET           = 0x80000
MEM_TOP_DOWN       = 0x100000
MEM_WRITE_WATCH    = 0x200000
MEM_PHYSICAL       = 0x400000
MEM_LARGE_PAGES  = 0x20000000
MEM_4MB_PAGES    = 0x80000000
SEC_FILE           = 0x800000
SEC_IMAGE         = 0x1000000
SEC_RESERVE       = 0x4000000
SEC_COMMIT        = 0x8000000
SEC_NOCACHE      = 0x10000000
SEC_LARGE_PAGES  = 0x80000000
MEM_IMAGE         = SEC_IMAGE
WRITE_WATCH_FLAG_RESET = 0x01
FILE_MAP_ALL_ACCESS = 0xF001F

# Don't psyco-optimize this class because it needs to be serialized.
class MemoryBasicInformation(object):
	"""
	Memory information object returned by L{VirtualQueryEx}.
	"""

	READABLE = (
				PAGE_EXECUTE_READ	   |
				PAGE_EXECUTE_READWRITE  |
				PAGE_EXECUTE_WRITECOPY  |
				PAGE_READONLY		   |
				PAGE_READWRITE		  |
				PAGE_WRITECOPY
	)

	WRITEABLE = (
				PAGE_EXECUTE_READWRITE  |
				PAGE_EXECUTE_WRITECOPY  |
				PAGE_READWRITE		  |
				PAGE_WRITECOPY
	)

	COPY_ON_WRITE = (
				PAGE_EXECUTE_WRITECOPY  |
				PAGE_WRITECOPY
	)

	EXECUTABLE = (
				PAGE_EXECUTE			|
				PAGE_EXECUTE_READ	   |
				PAGE_EXECUTE_READWRITE  |
				PAGE_EXECUTE_WRITECOPY
	)

	EXECUTABLE_AND_WRITEABLE = (
				PAGE_EXECUTE_READWRITE  |
				PAGE_EXECUTE_WRITECOPY
	)

	def __init__(self, mbi=None):
		"""
		@type  mbi: L{MEMORY_BASIC_INFORMATION} or L{MemoryBasicInformation}
		@param mbi: Either a L{MEMORY_BASIC_INFORMATION} structure or another
			L{MemoryBasicInformation} instance.
		"""
		if mbi is None:
			self.BaseAddress		= None
			self.AllocationBase	 = None
			self.AllocationProtect  = None
			self.RegionSize		 = None
			self.State			  = None
			self.Protect			= None
			self.Type			   = None
		else:
			self.BaseAddress		= mbi.BaseAddress
			self.AllocationBase	 = mbi.AllocationBase
			self.AllocationProtect  = mbi.AllocationProtect
			self.RegionSize		 = mbi.RegionSize
			self.State			  = mbi.State
			self.Protect			= mbi.Protect
			self.Type			   = mbi.Type

			# Only used when copying MemoryBasicInformation objects, instead of
			# instancing them from a MEMORY_BASIC_INFORMATION structure.
			if hasattr(mbi, 'content'):
				self.content = mbi.content
			if hasattr(mbi, 'filename'):
				self.content = mbi.filename

	def __contains__(self, address):
		"""
		Test if the given memory address falls within this memory region.
		@type  address: int
		@param address: Memory address to test.
		@rtype:  bool
		@return: C{True} if the given memory address falls within this memory
			region, C{False} otherwise.
		"""
		return self.BaseAddress <= address < (self.BaseAddress + self.RegionSize)

	def is_free(self):
		"""
		@rtype:  bool
		@return: C{True} if the memory in this region is free.
		"""
		return self.State == MEM_FREE

	def is_reserved(self):
		"""
		@rtype:  bool
		@return: C{True} if the memory in this region is reserved.
		"""
		return self.State == MEM_RESERVE

	def is_commited(self):
		"""
		@rtype:  bool
		@return: C{True} if the memory in this region is commited.
		"""
		return self.State == MEM_COMMIT

	def is_image(self):
		"""
		@rtype:  bool
		@return: C{True} if the memory in this region belongs to an executable
			image.
		"""
		return self.Type == MEM_IMAGE

	def is_mapped(self):
		"""
		@rtype:  bool
		@return: C{True} if the memory in this region belongs to a mapped file.
		"""
		return self.Type == MEM_MAPPED

	def is_private(self):
		"""
		@rtype:  bool
		@return: C{True} if the memory in this region is private.
		"""
		return self.Type == MEM_PRIVATE

	def is_guard(self):
		"""
		@rtype:  bool
		@return: C{True} if all pages in this region are guard pages.
		"""
		return self.is_commited() and bool(self.Protect & PAGE_GUARD)

	def has_content(self):
		"""
		@rtype:  bool
		@return: C{True} if the memory in this region has any data in it.
		"""
		return self.is_commited() and not bool(self.Protect & (PAGE_GUARD | PAGE_NOACCESS))

	def is_readable(self):
		"""
		@rtype:  bool
		@return: C{True} if all pages in this region are readable.
		"""
		return self.has_content() and bool(self.Protect & self.READABLE)

	def is_writeable(self):
		"""
		@rtype:  bool
		@return: C{True} if all pages in this region are writeable.
		"""
		return self.has_content() and bool(self.Protect & self.WRITEABLE)

	def is_copy_on_write(self):
		"""
		@rtype:  bool
		@return: C{True} if all pages in this region are marked as
			copy-on-write. This means the pages are writeable, but changes
			are not propagated to disk.
		@note:
			Tipically data sections in executable images are marked like this.
		"""
		return self.has_content() and bool(self.Protect & self.COPY_ON_WRITE)

	def is_executable(self):
		"""
		@rtype:  bool
		@return: C{True} if all pages in this region are executable.
		@note: Executable pages are always readable.
		"""
		return self.has_content() and bool(self.Protect & self.EXECUTABLE)

	def is_executable_and_writeable(self):
		"""
		@rtype:  bool
		@return: C{True} if all pages in this region are executable and
			writeable.
		@note: The presence of such pages make memory corruption
			vulnerabilities much easier to exploit.
		"""
		return self.has_content() and bool(self.Protect & self.EXECUTABLE_AND_WRITEABLE)


# typedef struct _MEMORY_BASIC_INFORMATION {
#	 PVOID BaseAddress;
#	 PVOID AllocationBase;
#	 DWORD AllocationProtect;
#	 SIZE_T RegionSize;
#	 DWORD State;
#	 DWORD Protect;
#	 DWORD Type;
# } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
class MEMORY_BASIC_INFORMATION(Structure):
	_fields_ = [
		('BaseAddress',		 SIZE_T),	# remote pointer
		('AllocationBase',	  SIZE_T),	# remote pointer
		('AllocationProtect',   DWORD),
		('RegionSize',		  SIZE_T),
		('State',			   DWORD),
		('Protect',			 DWORD),
		('Type',				DWORD),
	]
PMEMORY_BASIC_INFORMATION = POINTER(MEMORY_BASIC_INFORMATION)



# BOOL WINAPI ReadProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __out  LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesRead
# );
def ReadProcessMemory(hProcess, lpBaseAddress, nSize):
	_ReadProcessMemory = windll.kernel32.ReadProcessMemory
	_ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
	_ReadProcessMemory.restype  = bool

	lpBuffer			= ctypes.create_string_buffer(nSize)
	lpNumberOfBytesRead = SIZE_T(0)
	success = _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, byref(lpNumberOfBytesRead))
	if not success and GetLastError() != ERROR_PARTIAL_COPY:
		raise ctypes.WinError()
	return lpBuffer.raw[:lpNumberOfBytesRead.value]

# BOOL WINAPI WriteProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __in   LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesWritten
# );
def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer):
	_WriteProcessMemory = windll.kernel32.WriteProcessMemory
	_WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
	_WriteProcessMemory.restype  = bool

	nSize				   = len(lpBuffer)
	lpBuffer				= ctypes.create_string_buffer(lpBuffer)
	lpNumberOfBytesWritten  = SIZE_T(0)
	success = _WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, byref(lpNumberOfBytesWritten))
	if not success and GetLastError() != ERROR_PARTIAL_COPY:
		raise ctypes.WinError()
	return lpNumberOfBytesWritten.value
	
	
# SIZE_T WINAPI VirtualQueryEx(
#   __in	  HANDLE hProcess,
#   __in_opt  LPCVOID lpAddress,
#   __out	 PMEMORY_BASIC_INFORMATION lpBuffer,
#   __in	  SIZE_T dwLength
# );
def VirtualQueryEx(hProcess, lpAddress):
	_VirtualQueryEx = windll.kernel32.VirtualQueryEx
	_VirtualQueryEx.argtypes = [HANDLE, LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T]
	_VirtualQueryEx.restype  = SIZE_T

	lpBuffer  = MEMORY_BASIC_INFORMATION()
	dwLength  = sizeof(MEMORY_BASIC_INFORMATION)
	success   = _VirtualQueryEx(hProcess, lpAddress, byref(lpBuffer), dwLength)
	if success == 0:
		raise ctypes.WinError()
	return MemoryBasicInformation(lpBuffer)