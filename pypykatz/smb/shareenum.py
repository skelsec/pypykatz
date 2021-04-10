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
	
	async def run(self, target_q):
		try:
			conn_url = MSLDAPURLDecoder(self.url)
			connection = conn_url.get_client()
			_, err = await connection.connect()
			if err is not None:
				raise err
			
			adinfo = connection._ldapinfo
			domain_name = adinfo.distinguishedName.replace('DC','').replace('=','').replace(',','.')

			cnt = 0
			async for machine, err in connection.get_all_machines(attrs=['sAMAccountName', 'dNSHostName', 'objectSid']):
				if err is not None:
					raise err
					
				dns = machine.dNSHostName
				if dns is None:
					dns = '%s.%s' % (machine.sAMAccountName[:-1], domain_name)
				
				cnt += 1
				await target_q.put((str(machine.objectSid),str(dns)))
				await asyncio.sleep(0)
			return cnt, None
		except Exception as e:
			return cnt, e
	

async def shareenum_live(targets = None, from_ldap = False, smb_worker_count = 10, depth = 3, out_file = None, progress = False, max_items = None, dirsd = False, filesd = False, authmethod = 'ntlm', protocol_version = '2'):
	from aiosmb.commons.connection.url import SMBConnectionURL
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader
	from pypykatz.apypykatz import apypykatz


	if targets is None and from_ldap is None:
		raise Exception('Shareenum needs a list of targets or LDAP connection string')

	enumerator = SMBFileEnum(
		get_smb_url(), 
		worker_count = smb_worker_count, 
		depth = depth, 
		out_file = out_file, 
		show_pbar = progress,
		max_items = max_items,
		fetch_dir_sd = dirsd,
		fetch_file_sd = filesd
	)
	
	notfile = []
	for target in targets:
		try:
			f = open(target, 'r')
			f.close()
			enumerator.target_gens.append(FileTargetGen(target))
		except:
			notfile.append(target)
	
	if len(notfile) > 0:
		enumerator.target_gens.append(ListTargetGen(notfile))
	
	if from_ldap is True:
		ldap_url = get_ldap_url()
		enumerator.target_gens.append(LDAPTargetGen(ldap_url))

	if len(enumerator.target_gens) == 0:
		raise Exception('No suitable targets found!')

	await enumerator.run()
