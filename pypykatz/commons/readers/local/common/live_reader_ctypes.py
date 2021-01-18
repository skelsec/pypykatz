import os
import sys
import ctypes
import enum
import logging

from pypykatz.commons.readers.local.common.kernel32 import *
from pypykatz.commons.readers.local.common.psapi import *

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
	

def QueryDosDevice(drive_letter):
    buffer_length = 1024
    buf = ctypes.create_unicode_buffer(buffer_length)
    status = windll.kernel32.QueryDosDeviceW(drive_letter, buf, buffer_length)
    if status == 0:
        raise ctypes.WinError()
    return buf.value


def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if bitmask & 1:
            drives.append(letter + ':')
        bitmask >>= 1
    return drives

def get_device_prefixes():
    device_prefixes = {}
    drives = get_drives()
    for drive in drives:
        device_prefixes[QueryDosDevice(drive)] = drive
    return device_prefixes

DEVICE_PREFIXES = get_device_prefixes()

WINDOWS_BUILD_NUMBER = getWindowsBuild()
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
MAXIMUM_ALLOWED = 33554432
STATUS_INFO_LENGTH_MISMATCH = -1073741820
MAX_PATH_UNICODE = 1 << 15

# Get full normalized image path of a process using NtQuerySystemInformation
# It doesn't need any special privileges
def get_process_full_imagename(pid):
    _NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
    image_filename = ''
    buf = ctypes.create_unicode_buffer(0x1000)
    process_info = SYSTEM_PROCESS_ID_INFORMATION()
    process_info.ProcessId = ctypes.c_void_p(pid)
    process_info.ImageName.MaximumLength = len(buf)
    process_info.ImageName.Buffer = addressof(buf)
    status = _NtQuerySystemInformation(
        SystemProcessIdInformation,
        process_info,
        sizeof(process_info),
        None)
    if status == STATUS_INFO_LENGTH_MISMATCH:
        buf = ctypes.create_unicode_buffer(MAX_PATH_UNICODE)
        process_info.ImageName.MaximumLength = len(buf)
        process_info.ImageName.Buffer = addressof(buf)
        status = _NtQuerySystemInformation(
            SystemProcessIdInformation,
            process_info,
            sizeof(process_info),
            None)
    if status == 0:
        image_filename = str(process_info.ImageName.Buffer)
        if image_filename.startswith('\\Device\\'):
            for win_path in DEVICE_PREFIXES:
                if image_filename.startswith(win_path):
                    image_filename = DEVICE_PREFIXES[win_path] + image_filename[len(win_path):]
    else:
        image_filename = 'N/A'
    return image_filename

PS_PROTECTED_TYPE_STRINGS = [None,"Light","Full"]
PS_PROTECTED_SIGNER_STRINGS = [None, "Authenticode", "CodeGen", "Antimalware", "Lsa", 
                            "Windows", "WinTcb", "WinSystem", "StoreApp"]
PS_PROTECTED_TYPE_OLD_OS_STRINGS = [None,"System protected process"]

#https://msdn.microsoft.com/en-us/library/windows/desktop/ms683217(v=vs.85).aspx
#def enum_process_names():
#	pid_to_fullname = {}
#	
#	for pid in EnumProcesses():
#		if pid == 0:
#			continue
#
#		pid_to_fullname[pid] = get_process_full_imagename(pid)
#	return pid_to_fullname

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

def get_process_extended_basic_information(pid,process_handle=None):
    process_basic_info = PROCESS_EXTENDED_BASIC_INFORMATION()
    process_basic_info.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION)
    _NtQueryInformationProcess = windll.ntdll.NtQueryInformationProcess
    if process_handle == None:
        process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)

    status = _NtQueryInformationProcess(process_handle,
                                       ProcessBasicInformation,
                                       byref(process_basic_info),
                                       process_basic_info.Size,
                                       None)
    if status < 0:
        raise ctypes.WinError()
    CloseHandle(process_handle)
    return process_basic_info


def get_protected_process_infos(pid,process_handle=None):
    process_protection_infos = None
    _NtQueryInformationProcess = windll.ntdll.NtQueryInformationProcess
    if process_handle == None:
        process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if WINDOWS_BUILD_NUMBER >= WindowsMinBuild.WIN_8.value:
        protection_info = PS_PROTECTION()
        status = _NtQueryInformationProcess(process_handle,
                                           ProcessProtectionInformation,
                                           byref(protection_info),
                                           sizeof(protection_info),
                                           None)
        if status < 0:
            raise ctypes.WinError()
        if protection_info.Type > 0:
            process_protection_infos = {"level": protection_info.Level,
                                        "type": PS_PROTECTED_TYPE_STRINGS[protection_info.Type],
                                        "signer": PS_PROTECTED_SIGNER_STRINGS[protection_info.Signer],
                                        "audit": protection_info.Audit}
    else:
        _ps_extended_basic_information = get_process_extended_basic_information(pid,process_handle)
        if _ps_extended_basic_information.IsProtectedProcess:
            process_protection_infos = {"type": 'System protected process'}
    CloseHandle(process_handle)
    return process_protection_infos
	
def get_lsass_pid():
	pid_to_name = enum_process_names()
	for pid in pid_to_name:
		if pid_to_name[pid].lower().endswith('lsass.exe'):
			return pid
			
	raise Exception('Failed to find lsass.exe')
