import asyncio
import os

from pypykatz import logging
from msldap.commons.url import MSLDAPURLDecoder
from aiosmb.examples.smbshareenum import SMBFileEnum, ListTargetGen, FileTargetGen

def get_smb_url(authmethod = 'ntlm', protocol_version = '2', host = None):
	from winacl.functions.highlevel import get_logon_info
	info = get_logon_info()
	logonserver = info['logonserver']
	if host is not None:
		logonserver = host

	return 'smb%s+sspi-%s://%s\\%s@%s' % (protocol_version, authmethod, info['domain'], info['username'], logonserver)


def get_ldap_url(authmethod = 'ntlm', host = None):
	from winacl.functions.highlevel import get_logon_info
	info = get_logon_info()

	logonserver = info['logonserver']
	if host is not None:
		logonserver = host

	return 'ldap+sspi-%s://%s\\%s@%s' % (authmethod, info['domain'], info['username'], logonserver)

class LDAPTargetGen:
	def __init__(self, url):
		self.url = url
	
	async def generate(self):
		try:
			conn_url = MSLDAPURLDecoder(self.url)
			connection = conn_url.get_client()
			_, err = await connection.connect()
			if err is not None:
				raise err
			
			adinfo = connection._ldapinfo
			domain_name = adinfo.distinguishedName.replace('DC','').replace('=','').replace(',','.')

			async for machine, err in connection.get_all_machines(attrs=['sAMAccountName', 'dNSHostName', 'objectSid']):
				if err is not None:
					raise err
					
				dns = machine.dNSHostName
				if dns is None:
					dns = '%s.%s' % (machine.sAMAccountName[:-1], domain_name)
				
				yield str(machine.objectSid), str(dns), None

		except Exception as e:
			yield None, None, e
	

async def shareenum(smb_url, ldap_url = None, targets = None, smb_worker_count = 10, depth = 3, out_file = None, progress = False, max_items = None, dirsd = False, filesd = False, authmethod = 'ntlm', protocol_version = '2', output_type = 'str', max_runtime = None, exclude_share = ['print$'], exclude_dir = [], exclude_target = []):
	from aiosmb.commons.connection.url import SMBConnectionURL
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader
	from pypykatz.apypykatz import apypykatz


	#if targets is None and ldap_url is None:
	#	raise Exception('Shareenum needs a list of targets or LDAP connection string')
	
	if smb_url == 'auto':
		smb_url = get_smb_url(authmethod=authmethod, protocol_version=protocol_version)
	
	enumerator = SMBFileEnum(
		smb_url,
		worker_count = smb_worker_count, 
		depth = depth, 
		out_file = out_file, 
		show_pbar = progress,
		max_items = max_items,
		fetch_dir_sd = dirsd,
		fetch_file_sd = filesd,
		output_type = output_type,
		max_runtime = max_runtime,
		exclude_share = exclude_share,
		exclude_dir = exclude_dir,
		exclude_target = exclude_target
	)
	
	notfile = []
	if targets is not None:
		for target in targets:
			try:
				f = open(target, 'r')
				f.close()
				enumerator.target_gens.append(FileTargetGen(target))
			except:
				notfile.append(target)
		
		if len(notfile) > 0:
			enumerator.target_gens.append(ListTargetGen(notfile))
	
	if ldap_url is not None:
		if ldap_url == 'auto':
			ldap_url = get_ldap_url(authmethod=authmethod)
		enumerator.target_gens.append(LDAPTargetGen(ldap_url))

	if len(enumerator.target_gens) == 0:
		enumerator.enum_url = True
		#raise Exception('No suitable targets found!')

	await enumerator.run()
