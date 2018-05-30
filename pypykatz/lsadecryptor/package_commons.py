from abc import ABC, abstractmethod
import logging
from pypykatz.commons.common import *

class PackageTemplate:
	def __init__(self, package_name):
		self.package_name = package_name
	
	def log_template(self, struct_var_name, struct_template_obj):
		""""
		Generic logging function to show which template was selected for which structure
		"""
		logging.log(1, 'Package %s: Selecting template for %s: %s' % (self.package_name, struct_var_name, struct_template_obj.__name__))
	
	
	@staticmethod
	@abstractmethod
	def get_template(sysinfo):
		pass
		
class PackageDecryptor:
	def __init__(self, package_name):
		self.package_name = package_name
	
	def log_decryptor(self):
		pass
		
	def log_ptr(self, ptr, name, datasize = 0x50):
		"""
		Reads datasize bytes from the memory region pointed by the pointer.
		ptr = the pointer to be read
		name = display name for the memory structure, usually the data structure's name the pointer is pointing at
		"""
		pos = self.reader.tell()
		self.reader.move(ptr)
		data = self.reader.peek(datasize)
		self.reader.move(pos)
		logging.log(1, '%s: %s\n%s' % (name, hex(ptr), hexdump(data, start = ptr)))
		
	def walk_avl(self, node_ptr, result_ptr_list):
		"""
		Walks the AVL tree, extracts all OrderedPointer values and returns them in a list
		"""
		node = node_ptr.read(self.reader, override_finaltype = RTL_AVL_TABLE)
		if node.OrderedPointer.value != 0:
			result_ptr_list.append(node.OrderedPointer.value)
			if node.BalancedRoot.LeftChild.value != 0 :
				self.walk_avl(node.BalancedRoot.LeftChild, result_ptr_list)
			if node.BalancedRoot.RightChild.value != 0 :
				self.walk_avl(node.BalancedRoot.RightChild, result_ptr_list)
		
	def walk_list(self, entry_ptr, callback, max_walk = 255, override_ptr = None):
		"""
		Iterating over a linked list. Linked lists in packages are circural, so the end of the list is tested is the Flink is pointing to an address already seen.
		
		entry_ptr = pointer type object the will yiled the first entry when called read()
		callback = function that will be called when a new entry is found. callback method will be invoked with one parameter, the entry itself
		
		max_walk = limit the amount of entries to be iterating
		override_ptr = if this parameter is set the pointer will be resolved as if it would be pointing to this structure
		"""
		
		entries_seen = {}
		entries_seen[entry_ptr.location] = 1
		max_walk = max_walk
		self.log_ptr(entry_ptr.value, 'List entry -%s-' % entry_ptr.finaltype.__name__)
		while True:
			if override_ptr:
				entry = entry_ptr.read(self.reader, override_ptr)
			else:
				entry = entry_ptr.read(self.reader)
				
			callback(entry)
			
			max_walk -= 1
			logging.log(1, '%s next ptr: %x' % (entry.Flink.finaltype.__name__, entry.Flink.value))
			logging.log(1, '%s seen: %s' % (entry.Flink.finaltype.__name__, entry.Flink.value not in entries_seen))
			logging.log(1, '%s max_walk: %d' % (entry.Flink.finaltype.__name__, max_walk))
			if entry.Flink.value != 0 and entry.Flink.value not in entries_seen and max_walk != 0:
				entries_seen[entry.Flink.value] = 1
				self.log_ptr(entry.Flink.value, 'Next list entry -%s-' % entry.Flink.finaltype.__name__)
				entry_ptr = entry.Flink
			else:
				break
				
				
	