#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz import logging

"""
LDAP is not part of pypykatz directly. 
This is a wrapper for msldap, ldap3 and winsspi packages
"""

class LDAPCMDHelper:
	def __init__(self):
		self.live_keywords = ['ldap']
		self.keywords = ['ldap']
		
	def add_args(self, parser, live_parser):
		group = parser.add_parser('ldap', help='LDAP (live) related commands')
		group.add_argument('credential', help= 'Credential to be used')
		group.add_argument('cmd', choices=['spn', 'asrep','dump','custom'])
		group.add_argument('-o','--out-file', help= 'File to stroe results in')
		group.add_argument('-a','--attrs', action='append', help='DUMP and CUSTOM mode only. LDAP attributes to display. Can be stacked')
		group.add_argument('-f','--filter',  help='CUSTOM mode only. LDAP search filter')
		
		
		live_group = live_parser.add_parser('ldap', help='LDAP (live) related commands')
		live_group.add_argument('-c','--credential', help= 'Credential to be used, if omitted it will use teh credentials of the current user. If specified, it will try to impersonate the user. (requires the the target user has a session on the local computer)')
		live_group.add_argument('--dc-ip', help= 'IP address or hostname of the LDAP server. Optional. If omitted will use registry to check for the DC.')
		live_group.add_argument('cmd', choices=['spn', 'asrep','dump','custom'])
		live_group.add_argument('-o','--out-file', help= 'File to stroe results in')
		live_group.add_argument('-a','--attrs', action='append', help='DUMP and CUSTOM mode only. LDAP attributes to display. Can be stacked')
		live_group.add_argument('-f','--filter',  help='CUSTOM mode only. LDAP search filter')
		
	def execute(self, args):
		if args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
			
	def run_live(self, args):
		from msldap.core import MSLDAPCredential, MSLDAPTarget, MSLDAPConnection
		from msldap.ldap_objects import MSADUser
		from msldap import logger as msldaplogger
		from pypykatz.commons.winapi.machine import LiveMachine
		
		machine = LiveMachine()
	
		if args.credential:
			creds = MSLDAPCredential.from_connection_string(args.credential)
		else:
			creds = MSLDAPCredential.get_dummy_sspi()
		
		if args.dc_ip:
			target = MSLDAPTarget(args.dc_ip)
		else:
			target = MSLDAPTarget(machine.get_domain())
			
		connection = MSLDAPConnection(creds, target)
		connection.connect()
		
		try:
			adinfo = connection.get_ad_info()
			domain = adinfo.distinguishedName.replace('DC=','').replace(',','.')
		except Exception as e:
			logging.warning('[LDAP] Failed to get domain name from LDAP server. This is not normal, but happens. Reason: %s' % e)
			domain = machine.get_domain()
		
		if args.cmd == 'spn':
			logging.debug('Enumerating SPN user accounts...')
			cnt = 0
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_spn_users.txt'), 'w', newline='') as f:
					for user in connection.get_all_service_user_objects():
						cnt += 1
						f.write('%s/%s\r\n' % (domain, user.sAMAccountName))
			
			else:
				print('[+] SPN users')
				for user in connection.get_all_service_user_objects():
					cnt += 1
					print('%s/%s' % (domain, user.sAMAccountName))
			
			logging.debug('Enumerated %d SPN user accounts' % cnt)
			
		elif args.cmd == 'asrep':
			logging.debug('Enumerating ASREP user accounts...')
			ctr = 0
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_asrep_users.txt'), 'w', newline='') as f:
					for user in connection.get_all_knoreq_user_objects():
						ctr += 1
						f.write('%s/%s\r\n' % (domain, user.sAMAccountName))
			else:
				print('[+] ASREP users')
				for user in connection.get_all_knoreq_user_objects():
					ctr += 1
					print('%s/%s' % (domain, user.sAMAccountName))

			logging.debug('Enumerated %d ASREP user accounts' % ctr)
			
		elif args.cmd == 'dump':
			logging.debug('Enumerating ALL user accounts, this will take some time depending on the size of the domain')
			ctr = 0
			attrs = args.attrs if args.attrs is not None else MSADUser.TSV_ATTRS
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_ldap_users.tsv'), 'w', newline='', encoding ='utf8') as f:
					writer = csv.writer(f, delimiter = '\t')
					writer.writerow(attrs)
					for user in connection.get_all_user_objects():
						ctr += 1
						writer.writerow(user.get_row(attrs))

			else:
				logging.debug('Are you sure about this?')
				print('[+] Full user dump')
				print('\t'.join(attrs))
				for user in connection.get_all_user_objects():
					ctr += 1
					print('\t'.join([str(x) for x in user.get_row(attrs)]))

			
			logging.debug('Enumerated %d user accounts' % ctr)
			
		elif args.cmd == 'custom':
			if not args.filter:
				raise Exception('Custom LDAP search requires the search filter to be specified!')
			if not args.attrs:
				raise Exception('Custom LDAP search requires the attributes to be specified!')

			logging.debug('Perforing search on the AD with the following filter: %s' % args.filter)
			logging.debug('Search will contain the following attributes: %s' % ','.join(args.attrs))
			ctr = 0

			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_ldap_custom.tsv'), 'w', newline='') as f:
					writer = csv.writer(f, delimiter = '\t')
					writer.writerow(args.attrs)
					for obj in connection.pagedsearch(args.filter, args.attrs):
						ctr += 1
						writer.writerow([str(obj['attributes'].get(x, 'N/A')) for x in args.attrs])

			else:
				for obj in connection.pagedsearch(args.filter, args.attrs):
					ctr += 1
					print('\t'.join([str(obj['attributes'].get(x, 'N/A')) for x in args.attrs]))

			logging.debug('Custom search yielded %d results!' % ctr)
			
	def run(self, args):
		from msldap.core import MSLDAPCredential, MSLDAPTarget, MSLDAPConnection
		from msldap.ldap_objects import MSADUser
		from msldap import logger as msldaplogger
		
		if not args.credential:
			raise Exception('You must provide credentials when using ldap in platform independent mode.')
			
		creds = MSLDAPCredential.from_connection_string(args.credential)
		target = MSLDAPTarget.from_connection_string(args.credential)
			
		connection = MSLDAPConnection(creds, target)
		connection.connect()
		
		try:
			adinfo = connection.get_ad_info()
			domain = adinfo.distinguishedName.replace('DC=','').replace(',','.')
		except Exception as e:
			logging.warning('[LDAP] Failed to get domain name from LDAP server. This is not normal, but happens. Reason: %s' % e)
			domain = machine.get_domain()
		
		if args.cmd == 'spn':
			logging.debug('Enumerating SPN user accounts...')
			cnt = 0
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_spn_users.txt'), 'w', newline='') as f:
					for user in connection.get_all_service_user_objects():
						cnt += 1
						f.write('%s/%s\r\n' % (domain, user.sAMAccountName))
			
			else:
				print('[+] SPN users')
				for user in connection.get_all_service_user_objects():
					cnt += 1
					print('%s/%s' % (domain, user.sAMAccountName))
			
			logging.debug('Enumerated %d SPN user accounts' % cnt)
			
		elif args.cmd == 'asrep':
			logging.debug('Enumerating ASREP user accounts...')
			ctr = 0
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_asrep_users.txt'), 'w', newline='') as f:
					for user in connection.get_all_knoreq_user_objects():
						ctr += 1
						f.write('%s/%s\r\n' % (domain, user.sAMAccountName))
			else:
				print('[+] ASREP users')
				for user in connection.get_all_knoreq_user_objects():
					ctr += 1
					print('%s/%s' % (domain, user.sAMAccountName))
    
			logging.debug('Enumerated %d ASREP user accounts' % ctr)
			
		elif args.cmd == 'dump':
			logging.debug('Enumerating ALL user accounts, this will take some time depending on the size of the domain')
			ctr = 0
			attrs = args.attrs if args.attrs is not None else MSADUser.TSV_ATTRS
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_ldap_users.tsv'), 'w', newline='', encoding ='utf8') as f:
					writer = csv.writer(f, delimiter = '\t')
					writer.writerow(attrs)
					for user in connection.get_all_user_objects():
						ctr += 1
						writer.writerow(user.get_row(attrs))
    
			else:
				logging.debug('Are you sure about this?')
				print('[+] Full user dump')
				print('\t'.join(attrs))
				for user in connection.get_all_user_objects():
					ctr += 1
					print('\t'.join([str(x) for x in user.get_row(attrs)]))
    
			
			logging.debug('Enumerated %d user accounts' % ctr)
			
		elif args.cmd == 'custom':
			if not args.filter:
				raise Exception('Custom LDAP search requires the search filter to be specified!')
			if not args.attrs:
				raise Exception('Custom LDAP search requires the attributes to be specified!')
    
			logging.debug('Perforing search on the AD with the following filter: %s' % args.filter)
			logging.debug('Search will contain the following attributes: %s' % ','.join(args.attrs))
			ctr = 0
    
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_ldap_custom.tsv'), 'w', newline='') as f:
					writer = csv.writer(f, delimiter = '\t')
					writer.writerow(args.attrs)
					for obj in connection.pagedsearch(args.filter, args.attrs):
						ctr += 1
						writer.writerow([str(obj['attributes'].get(x, 'N/A')) for x in args.attrs])
    
			else:
				for obj in connection.pagedsearch(args.filter, args.attrs):
					ctr += 1
					print('\t'.join([str(obj['attributes'].get(x, 'N/A')) for x in args.attrs]))
    
			logging.debug('Custom search yielded %d results!' % ctr)
		