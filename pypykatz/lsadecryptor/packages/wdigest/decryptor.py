#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import json

from pypykatz.lsadecryptor.package_commons import PackageDecryptor
from pypykatz.commons.win_datatypes import LSA_UNICODE_STRING

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
	def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
		super().__init__('Wdigest', lsa_decryptor, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.credentials = []

	def find_first_entry(self):
		position = self.find_signature('wdigest.dll',self.decryptor_template.signature)
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	def add_entry(self, wdigest_entry):
		"""
		Changed the wdigest parsing, the struct only contains the pointers in the linked list, the actual data is read by 
		adding an offset to the current entry's position
		"""
		wc = WdigestCredential()
		wc.luid = wdigest_entry.luid
		
		#input(wdigest_entry.this_entry.value)
		self.reader.move(wdigest_entry.this_entry.value + self.decryptor_template.primary_offset)
		UserName = LSA_UNICODE_STRING(self.reader)
		DomainName = LSA_UNICODE_STRING(self.reader)
		Password = LSA_UNICODE_STRING(self.reader)

		wc.username = UserName.read_string(self.reader)
		wc.domainname = DomainName.read_string(self.reader)
		wc.encrypted_password = Password.read_maxdata(self.reader)
		wc.password = self.decrypt_password(wc.encrypted_password)

		
		self.credentials.append(wc)
	
	def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		except Exception as e:
			self.log('Failed to find Wdigest structs! Reason: %s' % e)
			return
		self.reader.move(entry_ptr_loc)
		entry_ptr = self.decryptor_template.list_entry(self.reader)
		self.walk_list(entry_ptr, self.add_entry)