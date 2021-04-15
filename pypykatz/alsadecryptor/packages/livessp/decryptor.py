#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import json
from pypykatz.alsadecryptor.package_commons import PackageDecryptor

class LiveSspCredential:
	def __init__(self):
		self.credtype = 'livessp'
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
		t = '\t== LiveSsp [%x]==\n' % self.luid
		t += '\tusername %s\n' % self.username
		t += '\tdomainname %s\n' % self.domainname
		t += '\tpassword %s\n' % self.password
		t += '\t\tpassword (hex)%s\n' % self.password_raw.hex()
		return t
		
class LiveSspDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
		super().__init__('LiveSsp', lsa_decryptor, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.credentials = []

	async def find_first_entry(self):
		position = await self.find_signature('msv1_0.dll',self.decryptor_template.signature)
		ptr_entry_loc = await self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = await self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	async def add_entry(self, ssp_entry):
		c = LiveSspCredential()
		c.luid = ssp_entry.LocallyUniqueIdentifier
			
		suppCreds = await ssp_entry.suppCreds.read(self.reader)
			
		c.username = await suppCreds.credentials.UserName.read_string(self.reader)
		c.domainname = await suppCreds.credentials.Domaine.read_string(self.reader)
		if suppCreds.credentials.Password.Length != 0:
			enc_data = await suppCreds.credentials.Password.read_maxdata(self.reader)
			if c.username.endswith('$') is True:
				c.password, c.password_raw = self.decrypt_password(enc_data, bytes_expected=True)
				if c.password is not None:
					c.password = c.password.hex()
			else:
				c.password, c.password_raw = self.decrypt_password(enc_data)
		
		self.credentials.append(c)
	
	async def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = await self.find_first_entry()
		except Exception as e:
			self.log('Failed to find structs! Reason: %s' % e)
			return
		await self.reader.move(entry_ptr_loc)
		entry_ptr = await self.decryptor_template.list_entry.load(self.reader)
		await self.walk_list(entry_ptr, self.add_entry)