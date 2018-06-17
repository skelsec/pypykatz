import os
import sys
import ctypes
import enum
import logging

from .kernel32 import *
from .psapi import *

class WindowsMinBuild(enum.Enum):
	WIN_XP = 2500
	WIN_2K3 = 3000
	WIN_VISTA = 5000
	WIN_7 = 7000
	WIN_8 = 8000
	WIN_BLUE = 9400
	WIN_10 = 9800

	
#utter microsoft bullshit commencing..
def getWindowsBuild():   
    class OSVersionInfo(ctypes.Structure):
        _fields_ = [
            ("dwOSVersionInfoSize" , ctypes.c_int),
            ("dwMajorVersion"      , ctypes.c_int),
            ("dwMinorVersion"      , ctypes.c_int),
            ("dwBuildNumber"       , ctypes.c_int),
            ("dwPlatformId"        , ctypes.c_int),
            ("szCSDVersion"        , ctypes.c_char*128)];
    GetVersionEx = getattr( ctypes.windll.kernel32 , "GetVersionExA")
    version  = OSVersionInfo()
    version.dwOSVersionInfoSize = ctypes.sizeof(OSVersionInfo)
    GetVersionEx( ctypes.byref(version) )    
    return version.dwBuildNumber
	
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000

SYNCHRONIZE = 0x00100000

STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
STANDARD_RIGHTS_ALL = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

if getWindowsBuild() >= WindowsMinBuild.WIN_VISTA.value:
	PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF
else:
	PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF
	
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

	
#https://msdn.microsoft.com/en-us/library/windows/desktop/ms683217(v=vs.85).aspx
def enum_process_names():
	pid_to_name = {}
	
	for pid in EnumProcesses():
		if pid == 0:
			continue
		pid_to_name[pid] = 'Not found'
		try:
			process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
		except Exception as e:
			continue
			
		pid_to_name[pid] = QueryFullProcessImageNameW(process_handle)
	return pid_to_name
	
	
def get_lsass_pid():
	pid_to_name = enum_process_names()
	for pid in pid_to_name:
		if pid_to_name[pid].lower().find('lsass.exe') != -1:
			return pid
			
	raise Exception('Failed to find lsass.exe')