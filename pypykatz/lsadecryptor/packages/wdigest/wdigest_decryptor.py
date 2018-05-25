import io
import logging
from pypykatz.lsadecryptor.packages.wdigest.wdigest_templates import *

class WdigestCredential:
	def __init__(self):
		self.credtype = 'wdigest'
		self.username = None
		self.domainname = None
		self.encrypted_password = None
		self.password = None
		self.luid = None
		
	@staticmethod
	def parse(wdigest_entry, reader, lsa_dec):
		wc = WdigestCredential()
		wc.luid = wdigest_entry.luid
		wc.username = wdigest_entry.UserName.read_string(reader)
		wc.domainname = wdigest_entry.DomainName.read_string(reader)
		wc.encrypted_password = wdigest_entry.Password.read_data(reader)
		t = lsa_dec.decrypt(wc.encrypted_password)
		if t and len(t) > 0:
			wc.password = t.decode('utf-16-le')
		return wc
	
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
		t += '\tusername %s\n' % self.username
		t += '\tdomainname %s\n' % self.domainname
		#t += 'encrypted_password %s\n' % self.encrypted_password.hex()
		t += '\tpassword %s\n' % self.password
		return t
		
class WdigestDecryptor():
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		self.module_name = 'wdigest'
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
	
	def log_ptr(self, ptr, name, datasize = 0x80):
		pos = self.reader.tell()
		self.reader.move(ptr)
		data = self.reader.peek(datasize)
		self.reader.move(pos)
		logging.log(1, '%s: %s\n%s' % (name, hex(ptr), hexdump(data, start = ptr)))
		
	def add_entry(self, wdigest_entry):
		wc = WdigestCredential.parse(wdigest_entry, self.reader, self.lsa_decryptor)
		self.credentials.append(wc)
		
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