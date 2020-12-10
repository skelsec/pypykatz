#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz import logger
import asyncio

"""
LDAP is not part of pypykatz directly. 
This is a wrapper for msldap
"""

class LDAPCMDArgs:
	def __init__(self):
		self.url = None
		self.verbose = 0
		self.no_interactive = False
		self.commands = ['login', 'i']

msldap_subcommand_list = []
msldap_epilog = 'FOR AVAILABLE SUBCOMMANDS TYPE "... ldap help" insted of "-h" '

class LDAPCMDHelper:
	def __init__(self):
		self.live_keywords = ['ldap']
		self.keywords = ['ldap']
		
	def add_args(self, parser, live_parser):
		group = parser.add_parser('ldap', help='LDAP client. Use "help" instead of "-h" to get the available subcommands')
		group.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		group.add_argument('url', help="LDAP connection string")
		group.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")
		
		live_group = live_parser.add_parser('ldap', help='LDAP (live) client. Use "help" instead of "-h" to get the available subcommands', epilog=msldap_epilog)
		live_group.add_argument('--host', help= 'Specify a custom logon server.')
		live_group.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'ntlm', help= 'Authentication method to use during login')
		live_group.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		live_group.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")

	def execute(self, args):
		if args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
			
	def run_live(self, args):
		from msldap.examples.msldapclient import amain
		from winacl.functions.highlevel import get_logon_info
		info = get_logon_info()

		logonserver = info['logonserver']
		if args.host is not None:
			logonserver = args.host

		la = LDAPCMDArgs()
		la.url = 'ldap+sspi-%s://%s\\%s@%s' % (args.authmethod, info['domain'], info['username'], logonserver)
		la.verbose = args.verbose

		if args.verbose > 1:
			print('Using the following auto-generated URL: %s' % la.url)
		if args.commands is not None and len(args.commands) > 0:
			la.commands = []
			if args.commands[0] == 'help':
				la.commands = ['help']
			else:
				if args.commands[0] != 'login':
					la.commands.append('login')
				
				for command in args.commands:
					la.commands.append(command)

		asyncio.run(amain(la))
			
	def run(self, args):
		from msldap.examples.msldapclient import amain
		la = LDAPCMDArgs()
		la.url = args.url
		la.verbose = args.verbose
		if args.commands is not None and len(args.commands) > 0:
			la.commands = []
			if args.commands[0] == 'help':
				la.commands = ['help']
			else:
				if args.commands[0] != 'login':
					la.commands.append('login')
				
				for command in args.commands:
					la.commands.append(command)

		asyncio.run(amain(la))
