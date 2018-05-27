#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging
import hashlib
from pypykatz.lsadecryptor.packages.wdigest.wdigest_templates import *

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
		t += '\tluid %s\n' % self.luid
		t += '\tkey_guid %s\n' % self.key_guid
		t += '\tmasterkey %s\n' % self.masterkey
		t += '\tsha1_masterkey %s\n' % self.sha1_masterkey
		return t
		
class DpapiDecryptor:
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		self.module_name = 'dpapi'
		self.reader = reader
		self.decryptor_template = decryptor_template
		self.lsa_decryptor = lsa_decryptor
		self.credentials = []
		
	def find_signature(self, modulename):
		logging.log(1, '[DpapiDecryptor] Searching for key struct signature')
		fl = self.reader.find_in_module(modulename,self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('[DpapiDecryptor] Signature was not found! %s' % self.decryptor_template.signature.hex())
		return fl[0]

	def find_first_entry(self, modulename):
		position = self.find_signature(modulename)
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
	
	def log_ptr(self, ptr, name, datasize = 0x80):
		pos = self.reader.tell()
		self.reader.move(ptr)
		data = self.reader.peek(datasize)
		self.reader.move(pos)
		logging.log(1, '%s: %s\n%s' % (name, hex(ptr), hexdump(data, start = ptr)))
		
	def add_entry(self, dpapi_entry):
		
		if dpapi_entry.keySize > 0:
			dec_masterkey = self.lsa_decryptor.decrypt(dpapi_entry.key)
			sha_masterkey = hashlib.sha1(dec_masterkey).hexdigest()
			
			c = DpapiCredential()
			c.luid = dpapi_entry.LogonId
			c.key_guid = dpapi_entry.KeyUid
			c.masterkey = dec_masterkey.hex()
			c.sha1_masterkey = sha_masterkey
			self.credentials.append(c)	
		
		
	def walk_list(self, entry_ptr, entry_ptr_location, callback, max_walk = 255, override_ptr = None):
		"""
		first_entry_ptr: pointer type object the will yiled the first entry when called read()
		first_entry_ptr_location: memory address of the first_entry_ptr so we will know when the list loops
		"""
		
		entries_seen = {}
		entries_seen[entry_ptr_location] = 1
		max_walk = max_walk
		self.log_ptr(entry_ptr.value, 'List entry -%s-' % entry_ptr.finaltype.__name__)
		while True:
			if override_ptr:
				entry = entry_ptr.read(self.reader, override_ptr)
			else:
				entry = entry_ptr.read(self.reader)
				
			callback(entry)
			
			max_walk -= 1
			logging.log(1, '%s next ptr: %x' % (entry.Flink.finaltype.__name__, entry.Flink.value))
			logging.log(1, '%s seen: %s' % (entry.Flink.finaltype.__name__, entry.Flink.value not in entries_seen))
			logging.log(1, '%s max_walk: %d' % (entry.Flink.finaltype.__name__, max_walk))
			if entry.Flink.value != 0 and entry.Flink.value not in entries_seen and max_walk != 0:
				entries_seen[entry.Flink.value] = 1
				self.log_ptr(entry.Flink.value, 'Next list entry -%s-' % entry.Flink.finaltype.__name__)
				entry_ptr = entry.Flink
			else:
				break
	
	def start(self):
		for modulename in ['lsasrv.dll','dpapisrv.dll']:
			try:
				entry_ptr_value, entry_ptr_loc = self.find_first_entry(modulename)
			except Exception as e:
				logging.log(1,'Failed to find Dpapi structs! Reason: %s' % e)
				continue
			self.reader.move(entry_ptr_loc)
			entry_ptr = self.decryptor_template.list_entry(self.reader)
			self.walk_list(entry_ptr, entry_ptr_loc, self.add_entry)