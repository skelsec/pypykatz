import winreg
import ntpath

from pypykatz.commons.readers.local.common.winreg import *

class LiveRegistryHive:
	def __init__(self, hive_name, root = winreg.HKEY_LOCAL_MACHINE):
		self.hive_name = hive_name
		self.root = root
		
	def close(self):
		return

	def setup(self):
		self.header = NTRegistryHeadr.read(self.reader)
		self.root = self.search_root_key()
		
	def find_key(self, key_path, throw = True):
		if self.root is None:
			self.setup()
		if key_path == '' or key_path is None:
			return self.root
			
		key_path = self.hive_name + '\\' + key_path
		
		print(self.root)
		print(key_path)
		access = winreg.KEY_READ
		#if key_path.find('\\SAM\\') != -1:
		#	access = 0x00080000
		
		try:
			key = winreg.OpenKeyEx(self.root, key_path, access= access) #access mask needs to be WRITE_OWNER
		except Exception as e:
			if throw is True:
				raise e
			else:
				print('ret none!')
				return None
		return key
		
	def enum_key(self, key_path, throw = True):
		if self.root is None:
			self.setup()
		
		#key_path = self.hive_name + '\\' + key_path
		key = self.find_key(key_path, throw)
		names = []
		i = 0
		while True:
			try:
				name = winreg.EnumKey(key, i)
				names.append(name)
				i+= 1
			except Exception as e:
				print(e)
				break
				
		return names
		
		
	def list_values(self, key):
		if self.root is None:
			self.setup()
		
		values = []
		i = 0
		while True:
			try:
				value = winreg.EnumValue(key, i)
				values.append(value[0].encode())
				i+= 1
			except Exception as e:
				print(e)
				break
				
		return values
		
	def get_value(self, value_path, throw = True):
		if self.root is None:
			self.setup()
		key_path = ntpath.dirname(value_path)
		value_name = ntpath.basename(value_path)
		if value_name == 'default':
			value_name = ''
		
		key = self.find_key(key_path, throw)
		print('vk %s' % key)
		print(value_name)
		if key is None:
			return None
			
		res = winreg.QueryValueEx(key, value_name)
		return (res[1], res[0])
		
	def get_class(self, key_path, throw = True):
		if self.root is None:
			self.setup()
			
		pkey = winreg.HKEY_LOCAL_MACHINE
		key_path = self.hive_name + '\\' + key_path
		for name in key_path.split('\\'):
			pkey = RegOpenKey(pkey, name)
	
		ki = RegQueryInfoKey(pkey)		
		return ki[0].decode()
		
	
	