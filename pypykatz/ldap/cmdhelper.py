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
		raise Exception('Coming soon...')
			
	def run(self, args):
		raise Exception('Coming soon...')
		