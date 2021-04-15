#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import json
import hashlib
from pypykatz.alsadecryptor.package_commons import PackageDecryptor

class DpapiCredential:
	def __init__(self):
		self.credtype = 'dpapi'
		self.luid = None
		self.key_guid = None
		self.masterkey = None
		self.sha1_masterkey = None
	
	def to_dict(self):
		t = {}
		t['credtype'] = self.credtype
		t['key_guid'] = self.key_guid
		t['masterkey'] = self.masterkey
		t['sha1_masterkey'] = self.sha1_masterkey
		t['luid'] = self.luid
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict())
		
	def __str__(self):
		t = '\t== DPAPI [%x]==\n' % self.luid
		t += '\t\tluid %s\n' % self.luid
		t += '\t\tkey_guid %s\n' % self.key_guid
		t += '\t\tmasterkey %s\n' % self.masterkey
		t += '\t\tsha1_masterkey %s\n' % self.sha1_masterkey
		return t
		
class DpapiDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
		super().__init__('Dpapi', lsa_decryptor, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.credentials = []
		

	async def find_first_entry(self, modulename):
		position = await self.find_signature(modulename, self.decryptor_template.signature)
		ptr_entry_loc = await self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = await self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	async def add_entry(self, dpapi_entry):
		
		if dpapi_entry and dpapi_entry.keySize > 0: #and dpapi_entry.keySize % 8 == 0:
			dec_masterkey, raw_dec = self.decrypt_password(dpapi_entry.key, bytes_expected = True)
			sha_masterkey = hashlib.sha1(dec_masterkey).hexdigest()
			
			c = DpapiCredential()
			c.luid = dpapi_entry.LogonId
			c.key_guid = dpapi_entry.KeyUid
			c.masterkey = dec_masterkey.hex()
			c.sha1_masterkey = sha_masterkey
			self.credentials.append(c)	
	
	async def start(self):
		for modulename in ['lsasrv.dll','dpapisrv.dll']:
			try:
				entry_ptr_value, entry_ptr_loc = await self.find_first_entry(modulename)
			except Exception as e:
				self.log('Failed to find structs! Reason: %s' % e)
				continue
			await self.reader.move(entry_ptr_loc)
			entry_ptr = await self.decryptor_template.list_entry.load(self.reader)
			await self.walk_list(entry_ptr, self.add_entry)