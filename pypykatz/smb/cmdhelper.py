

#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz import logging
import asyncio

"""
LDAP is not part of pypykatz directly.
This is a wrapper for aiosmb
"""

class SMBCMDArgs:
	def __init__(self):
		self.smb_url = None
		self.verbose = 0
		self.silent = True
		self.smb_url = None
		self.no_interactive = False
		self.commands = ['login', 'i']

smb_live_epilog = 'FOR AVAILABLE SUBCOMMANDS TYPE "... smb help" insted of "-h" '
class SMBCMDHelper:
	def __init__(self):
		self.live_keywords = ['smb']
		self.keywords = ['smb']
		
	def add_args(self, parser, live_parser):
		group = parser.add_parser('smb', help='SMB client. Use "help" instead of "-h" to get the available subcommands')
		group.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		group.add_argument('url', help="SMB connection string")
		group.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")
		
		live_group = live_parser.add_parser('smb', help='SMB (live) client. Use "help" instead of "-h" to get the available subcommands', epilog=smb_live_epilog)
		live_group.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'ntlm', help= 'Authentication method to use during login')
		live_group.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_group.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		live_group.add_argument('host', help='Target host to connect to')
		live_group.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")
		
	def execute(self, args):
		if args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
			
	def run_live(self, args):
		from aiosmb.examples.smbclient import amain
		from winacl.functions.highlevel import get_logon_info
		info = get_logon_info()
		la = SMBCMDArgs()
		la.smb_url = 'smb%s+sspi-%s://%s\\%s@%s' % (args.protocol_version, args.authmethod, info['domain'], info['username'], args.host)
		la.verbose = args.verbose
		print(la.smb_url)

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
		from aiosmb.examples.smbclient import amain
		la = SMBCMDArgs()
		la.smb_url = args.url
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
