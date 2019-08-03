
from pypykatz.commons.readers.local.common.advapi32 import *
from pypykatz.commons.readers.local.common.psapi import EnumProcesses
from pypykatz.commons.readers.local.common.kernel32 import OpenProcess, CloseHandle
from pypykatz.commons.readers.local.common.privileges import RtlAdjustPrivilege
from pypykatz.commons.readers.local.common.privileges_types import PrivilegeValues

tokenprivs = (TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072 | 4))

SYNCHRONIZE                     = 0x00100000

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx

PROCESS_CREATE_PROCESS           = 0x0080 # Required to create a process.
PROCESS_CREATE_THREAD            = 0x0002 # Required to create a thread.
PROCESS_DUP_HANDLE               = 0x0040 # Required to duplicate a handle using DuplicateHandle.
PROCESS_QUERY_INFORMATION        = 0x0400 # Required to retrieve certain information about a process, such as its token, exit code, and priority class = see OpenProcessToken #.
PROCESS_QUERY_LIMITED_INFORMATION= 0x1000 # Required to retrieve certain information about a process = see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName #. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.  Windows Server 2003 and Windows XP:  This access right is not supported.
PROCESS_SET_INFORMATION          = 0x0200 # Required to set certain information about a process, such as its priority class = see SetPriorityClass #.
PROCESS_SET_QUOTA                = 0x0100 # Required to set memory limits using SetProcessWorkingSetSize.
PROCESS_SUSPEND_RESUME           = 0x0800 # Required to suspend or resume a process.
PROCESS_TERMINATE                = 0x0001 # Required to terminate a process using TerminateProcess.
PROCESS_VM_OPERATION             = 0x0008 # Required to perform an operation on the address space of a process = see VirtualProtectEx and WriteProcessMemory #.
PROCESS_VM_READ                  = 0x0010 # Required to read memory in a process using ReadProcessMemory.
PROCESS_VM_WRITE                 = 0x0020 # Required to write to memory in a process using WriteProcessMemory.
PROCESS_ALL_ACCESS               = (PROCESS_CREATE_PROCESS
                                  | PROCESS_CREATE_THREAD
                                  | PROCESS_DUP_HANDLE
                                  | PROCESS_QUERY_INFORMATION
                                  | PROCESS_QUERY_LIMITED_INFORMATION
                                  | PROCESS_SET_INFORMATION
                                  | PROCESS_SET_QUOTA
                                  | PROCESS_SUSPEND_RESUME
                                  | PROCESS_TERMINATE
                                  | PROCESS_VM_OPERATION
                                  | PROCESS_VM_READ
                                  | PROCESS_VM_WRITE
                                  | SYNCHRONIZE)

def getsystem_token():
	try:
		RtlAdjustPrivilege(PrivilegeValues.SE_DEBUG.value)
	except Exception as e:
		logger.error('Failed to obtain SE_BACKUP privilege! Registry dump will not work! Reason: %s' % str(e))
		raise e
			
	
	for pid in EnumProcesses():
		print(pid)
		proc_handle = None
		try:
			proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
			print('Proc handle for PID %s is: %s' % (proc_handle, pid))
		except Exception as e:
			print('Failed to open process pid %s Reason: %s' % (pid, str(e)))
			continue
		
		else:
			token_handle = None
			try:
				token_handle = OpenProcessToken(proc_handle, DesiredAccess = tokenprivs)
			except Exception as e:
				print('Failed get token from process pid %s Reason: %s' % (pid, str(e)))
				continue
			else:
				
				sid = GetTokenInformation(token_handle, TokenUser)
				print('Token for PID %s has SID of %s' % (pid, sid))
				
				
			finally:
				if token_handle is not None:
					CloseHandle(token_handle)
		
		finally:
			if proc_handle is not None:
				CloseHandle(proc_handle)
	
if __name__ == '__main__':
	getsystem_token()