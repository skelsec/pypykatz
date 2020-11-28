#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import argparse
from pypykatz import logging

"""
Kerberos is not part of pypykatz directly. 
This is a wrapper for minikerberos and winsspi packages
"""

class KerberosCMDHelper:
	def __init__(self):
		self.live_keywords = ['kerberos']
		self.keywords = ['kerberos']
		
	def add_args(self, parser, live_parser):
		live_subcommand_parser = argparse.ArgumentParser(add_help=False)
		live_kerberos_subparsers = live_subcommand_parser.add_subparsers(help = 'live_kerberos_module')
		live_kerberos_subparsers.required = True
		live_kerberos_subparsers.dest = 'live_kerberos_module'
		
		live_roast_parser = live_kerberos_subparsers.add_parser('roast', help = 'Automatically run spnroast and asreproast')
		live_tgs_parser = live_kerberos_subparsers.add_parser('tgs', help = 'Request a TGS ticket for a given service')

		live_parser.add_parser('kerberos', help = 'Kerberos related commands', parents=[live_subcommand_parser])

		#offline part
		kerberos_group = parser.add_parser('kerberos', help='Kerberos related commands')
		kerberos_subparsers = kerberos_group.add_subparsers()
		kerberos_subparsers.required = True
		kerberos_subparsers.dest = 'kerberos_module'

		tgt_parser = kerberos_subparsers.add_parser('tgt', help = 'Fetches a TGT for a given user')
		tgt_parser.add_argument('url', help='user credentials in URL format')
		tgt_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')

		tgs_parser = kerberos_subparsers.add_parser('tgs', help = 'Fetches a TGS for a given service/user')
		tgs_parser.add_argument('url', help='user credentials in URL format')
		tgs_parser.add_argument('spn', help='SPN string of the service to request the ticket for')
		tgs_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')

		brute_parser = kerberos_subparsers.add_parser('brute', help = 'Bruteforcing usernames')
		brute_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
		brute_parser.add_argument('address', help='Kerberos server IP/hostname')
		brute_parser.add_argument('targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		asreproast_parser = kerberos_subparsers.add_parser('asreproast', help='asreproast')
		asreproast_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
		asreproast_parser.add_argument('address', help='Kerberos server IP/hostname')
		asreproast_parser.add_argument('targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		spnroast_parser = kerberos_subparsers.add_parser('spnroast', help = 'kerberoast/spnroast')
		spnroast_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
		spnroast_parser.add_argument('url', help='user credentials in URL format')
		spnroast_parser.add_argument('targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		s4u_parser = kerberos_subparsers.add_parser('s4u', help = 'Gets an S4U2proxy ticket impersonating given user')
		s4u_parser.add_argument('url', help='user credentials in URL format')
		s4u_parser.add_argument('spn', help='SPN string of the service to request the ticket for')
		s4u_parser.add_argument('targetuser', help='')
		s4u_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')
		
	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
			
	def run_live(self, args):
		from winsspi.sspi import KerberoastSSPI
		from minikerberos.common.utils import TGSTicket2hashcat, TGTTicket2hashcat
		from minikerberos.security import APREPRoast
		from minikerberos.network.clientsocket import KerberosClientSocket
		from minikerberos.common.target import KerberosTarget
		from pypykatz.commons.winapi.machine import LiveMachine
		
		if args.live_kerberos_module == 'roast':
			pass
			#tgt_parser.add_argument('url', help='user credentials in URL format')
			#tgt_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')
		
		elif args.live_kerberos_module == 'tgs':
			pass
			#tgt_parser.add_argument('url', help='user credentials in URL format')
			#tgt_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')
		
	def run(self, args):
		raise NotImplementedError('Platform independent kerberos not implemented!')

		if args.kerberos_module == 'tgt':
			pass
			#tgt_parser.add_argument('url', help='user credentials in URL format')
			#tgt_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')
		
		elif args.kerberos_module == 'tgs':
			pass
			#tgs_parser.add_argument('url', help='user credentials in URL format')
			#tgs_parser.add_argument('spn', help='SPN string of the service to request the ticket for')
			#tgs_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')
		
		elif args.kerberos_module == 'brute':
			pass
			#brute_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
			#brute_parser.add_argument('address', help='Kerberos server IP/hostname')
			#brute_parser.add_argument('targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		elif args.kerberos_module == 'asreproast':
			pass
			#asreproast_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
			#asreproast_parser.add_argument('address', help='Kerberos server IP/hostname')
			#asreproast_parser.add_argument('targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')
		
		elif args.kerberos_module == 'spnroast':
			pass
			#spnroast_parser.add_argument('-d','--domain', help='Domain name (realm). This overrides any other domain spec that the users might have.')
			#spnroast_parser.add_argument('url', help='user credentials in URL format')
			#spnroast_parser.add_argument('targets', nargs='*', help = 'username or file with usernames(one per line). Must be in username@domain format, unless you specified --domain then only the username is needed.You can specify mutliple usernames or files separated by space')

		elif args.kerberos_module == 's4u':
			pass
			#s4u_parser.add_argument('url', help='user credentials in URL format')
			#s4u_parser.add_argument('spn', help='SPN string of the service to request the ticket for')
			#s4u_parser.add_argument('targetuser', help='')
			#s4u_parser.add_argument('-o','--out-file', help='Output file to store the TGT in. CCACHE format.')