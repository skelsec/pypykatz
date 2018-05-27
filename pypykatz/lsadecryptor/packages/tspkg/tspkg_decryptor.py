#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging
from pypykatz.lsadecryptor.packages.wdigest.wdigest_templates import *

class TspkgCredential:
	def __init__(self):
		self.credtype = 'tspkg'
		self.username = None
		self.domainname = None
		self.password = None
		self.luid = None
	
	def to_dict(self):
		t = {}
		t['credtype'] = self.credtype
		t['username'] = self.username
		t['domainname'] = self.domainname
		t['password'] = self.password
		t['luid'] = self.luid
		return t
	def to_json(self):
		return json.dumps(self.to_dict())
		
	def __str__(self):
		t = '\t== WDIGEST [%x]==\n' % self.luid
		t += '\tusername %s\n' % self.username
		t += '\tdomainname %s\n' % self.domainname
		#t += 'encrypted_password %s\n' % self.encrypted_password.hex()
		t += '\tpassword %s\n' % self.password
		return t
		
class TspkgDecryptor():
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		self.module_name = 'tspkg'
		self.reader = reader
		self.decryptor_template = decryptor_template
		self.lsa_decryptor = lsa_decryptor
		self.credentials = []
		
	def find_signature(self):
		logging.log(1, '[TspkgDecryptor] Searching for key struct signature')
		fl = self.reader.find_in_module('tspkg.dll',self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('[TspkgDecryptor] Signature was not found! %s' % self.decryptor_template.signature.hex())
		return fl[0]

	def find_first_entry(self):
		position = self.find_signature()
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.avl_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
	
	def log_ptr(self, ptr, name, datasize = 0x80):
		pos = self.reader.tell()
		self.reader.move(ptr)
		data = self.reader.peek(datasize)
		self.reader.move(pos)
		logging.log(1, '%s: %s\n%s' % (name, hex(ptr), hexdump(data, start = ptr)))
		
	def walk_avl(self, node_ptr, result_ptr_list):
		"""
		Here I am @3AM searching left and right for that pointer...
		"""
		node = node_ptr.read(self.reader, override_finaltype = RTL_AVL_TABLE)
		if node.OrderedPointer.value != 0:
			result_ptr_list.append(node.OrderedPointer.value)
			if node.BalancedRoot.LeftChild.value != 0 :
				self.walk_avl(node.BalancedRoot.LeftChild, result_ptr_list)
			if node.BalancedRoot.RightChild.value != 0 :
				self.walk_avl(node.BalancedRoot.RightChild, result_ptr_list)
	
	def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		except Exception as e:
			logging.log(1,'Failed to find Wdigest structs! Reason: %s' % e)
			return
		result_ptr_list = []
		self.reader.move(entry_ptr_value)
		start_node = PRTL_AVL_TABLE(self.reader).read(self.reader)
		self.walk_avl(start_node.BalancedRoot.RightChild, result_ptr_list)
		for ptr in result_ptr_list:
			self.log_ptr(ptr, self.decryptor_template.credential_struct.__name__, datasize= 0x100)
			self.reader.move(ptr)
			credential_struct = self.decryptor_template.credential_struct(self.reader)
			primary_credential = credential_struct.pTsPrimary.read(self.reader)
			
			c = TspkgCredential()
			c.luid = credential_struct.LocallyUniqueIdentifier
			
			
			c.username = primary_credential.credentials.UserName.read_string(self.reader)
			c.domainname = primary_credential.credentials.Domaine.read_string(self.reader)
			c.password = primary_credential.credentials.Password.read_string(self.reader)
			
			self.credentials.append(c)